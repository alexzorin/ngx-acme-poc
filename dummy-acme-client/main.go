package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eggsampler/acme/v3"
)

type clientState struct {
	ACMEAccounts     map[string]acmeCredential `json:"acme_accounts"`
	Certificates     map[string]certificate    `json:"certificates"`
	LastServerConfig []server                  `json:"last_server_config"`
	mu               sync.Mutex
	dirty            bool
}

type acmeCredential struct {
	AccountKeyPEM string `json:"account_key"`
	Thumbprint    string `json:"thumbprint"`
}

type certificate struct {
	CertificateChainPEM string `json:"certificate"`
	CertificateKeyPEM   string `json:"certificate_key"`
}

type server struct {
	ServerNames []string `json:"server_names"`
}

type updateBroker struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

var (
	settings struct {
		storagePath      string
		acmeServer       string
		acmeContactEmail string
	}

	state clientState

	acmeClient  *acme.Client
	acmeAccount *acme.Account

	serversCh chan []server
	resyncCh  chan struct{}

	broker *updateBroker

	lastUpdate   []byte
	lastUpdateAt int64
	lastUpdateMu sync.RWMutex
)

func main() {
	settings.storagePath = "dummy-acme-client.json"
	settings.acmeServer = "https://acme-staging-v02.api.letsencrypt.org/directory"
	settings.acmeContactEmail = ""

	if err := state.load(); err != nil {
		log.Fatalf("Failed to load client state: %v", err)
	}
	// We want to generate an account key for the ACME server fairly early
	// so that we can get the thumbprint to the nginx workers quickly.
	// We don't actually need to register an account to know the thumbprint.
	if _, err := generateAccountKey(); err != nil {
		log.Fatalf("Failed to generate ACME account key: %v", err)
	}
	if err := state.save(); err != nil {
		log.Fatalf("Failed to save client state: %v", err)
	}

	broker = &updateBroker{
		subs: make(map[chan []byte]struct{}),
	}

	serversCh = make(chan []server, 1)
	go updateCertificates()

	resyncCh = make(chan struct{})
	go processSyncs()

	http.HandleFunc("/set-servers", handleSetServers)
	http.HandleFunc("/sync", handleSync)
	http.HandleFunc("/certificates", handleGetCertificates)
	log.Fatal(http.ListenAndServe("127.0.0.1:41934", nil))
}

func updateCertificates() {
	var previous []byte
	for {
		servers := <-serversCh

		// Don't do duplicative work. Multiple nginx workers will send us the same server list,
		// but we only need to check the certificates once if nothing has changed.
		buf, _ := json.Marshal(servers)
		if previous != nil && bytes.Equal(buf, previous) {
			continue
		}
		previous = buf

		state.mu.Lock()
		state.LastServerConfig = servers
		state.dirty = true
		state.mu.Unlock()

		log.Printf("Checking certificates for %d servers", len(servers))
		for _, server := range servers {
			if err := checkCertificate(server); err != nil {
				log.Printf("Failed to obtain certificate for server with names %v: %v", server.ServerNames, err)
			}
		}

	}
}

func processSyncs() {
	work := func() []byte {
		certsJSON := state.certificatesJSON()
		buf, _ := json.Marshal(map[string]any{
			"certificates": json.RawMessage(certsJSON),
			"thumbprint":   state.accountThumbprint(),
		})
		lastUpdateMu.Lock()
		lastUpdate = buf
		lastUpdateAt = time.Now().UnixMicro()
		lastUpdateMu.Unlock()
		return certsJSON
	}

	// Seed an initial response
	work()

	// Then do rsyncs
	for {
		<-resyncCh

		log.Printf("Publishing certificates to %d workers", len(broker.subs))
		certsJSON := work()

		broker.publish(certsJSON)
	}
}

func handleSetServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Servers []server `json:"servers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// The channel is buffered with 1 capacity, but if even that is blocking,
	// then it's probably going to be safe to just drop the send here because
	// it's going to be duplicative anyway.
	select {
	case serversCh <- request.Servers:
	default:
	}

}

func handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err != nil {
			since = v
		}
	}

	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)

	var response []byte

	// If we have an update newer than the client's `since`, send a response immediately.
	lastUpdateMu.RLock()
	if lastUpdateAt > since {
		response = make([]byte, len(lastUpdate))
		copy(response, lastUpdate)
	}
	lastUpdateMu.RUnlock()

	if response != nil {
		io.Copy(w, bytes.NewReader(lastUpdate))
		return
	}

	ch := broker.subscribe()
	defer broker.unsubscribe(ch)

	json.NewEncoder(w).Encode(map[string]any{
		"certificates": json.RawMessage(<-ch),
		"thumbprint":   acmeAccount.Thumbprint,
	})
}

func handleGetCertificates(w http.ResponseWriter, r *http.Request) {
	log.Printf("Certificates request from %s", r.RemoteAddr)
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	certs := make(map[string][2]string)

	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkDER, _ := x509.MarshalPKCS8PrivateKey(pk)
	pkPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkDER,
	})

	for _, server := range state.LastServerConfig {
		if len(server.ServerNames) == 0 {
			continue
		}

		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(8555),
			DNSNames:     server.ServerNames,
		}
		cert, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &pk.PublicKey, pk)
		if err != nil {
			log.Printf("Generating certificate failed: %v", err)
			http.Error(w, "Generating certificate failed", http.StatusInternalServerError)
			return
		}
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})
		for _, serverName := range server.ServerNames {
			certs[serverName] = [2]string{string(certPEM), string(pkPEM)}
		}
	}

	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Certificates map[string][2]string `json:"certificates"`
	}{Certificates: certs})
}

// domainsKey produces a normalized map key for a given unsorted list of DNS names.
func domainsKey(domains []string) string {
	domainsCopy := make([]string, len(domains))
	for i := range domains {
		domainsCopy[i] = strings.ToLower(domains[i])
	}
	sort.Strings(domainsCopy)
	return strings.Join(domainsCopy, ",")
}

func (cs *clientState) load() error {
	f, err := os.Open(settings.storagePath)

	// If the state file doesn't exist, that's okay, let's make one from scratch
	if os.IsNotExist(err) {
		cs.ACMEAccounts = make(map[string]acmeCredential)
		cs.Certificates = make(map[string]certificate)
		cs.dirty = true
		return nil
	} else if err != nil {
		return fmt.Errorf("couldn't open state file: %w", err)
	}

	defer f.Close()

	cs.mu.Lock()
	if err := json.NewDecoder(f).Decode(cs); err != nil {
		return fmt.Errorf("state file was not valid json: %w", err)
	}
	cs.dirty = false
	cs.mu.Unlock()

	return nil
}

func (cs *clientState) save() error {
	if !cs.dirty {
		return nil
	}
	cs.mu.Lock()
	buf, err := json.Marshal(cs)
	cs.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.WriteFile(settings.storagePath, buf, 0600); err != nil {
		return err
	}
	cs.dirty = false
	return nil
}

func (cs *clientState) existingCertificateForServer(s *server) *certificate {
	key := domainsKey(s.ServerNames)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cert, exists := cs.Certificates[key]
	if exists {
		return &certificate{
			CertificateChainPEM: cert.CertificateChainPEM,
			CertificateKeyPEM:   cert.CertificateChainPEM,
		}
	}
	return nil
}

func (cs *clientState) addCertificateForServer(s *server, cert *certificate) {
	key := domainsKey(s.ServerNames)
	cs.mu.Lock()
	cs.Certificates[key] = *cert
	cs.dirty = true
	cs.mu.Unlock()
}

func (cs *clientState) certificatesJSON() []byte {
	m := map[string]certificate{}
	cs.mu.Lock()
	for k, v := range cs.Certificates {
		m[k] = v
	}
	cs.mu.Unlock()
	buf, _ := json.Marshal(m)
	return buf
}

func (cs *clientState) accountThumbprint() string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	acc, exists := cs.ACMEAccounts[settings.acmeServer]
	if exists {
		return acc.Thumbprint
	}
	return ""
}

func generateAccountKey() (acmeCredential, error) {
	_, exists := state.ACMEAccounts[settings.acmeServer]
	if !exists {
		log.Printf("Generating a new ACME account key ...")

		privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return acmeCredential{}, fmt.Errorf("couldn't generate private key for ACME account: %w", err)
		}

		keyDER, _ := x509.MarshalPKCS8PrivateKey(privkey)
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})

		thumbprint, _ := acme.JWKThumbprint(privkey.Public())

		state.ACMEAccounts[settings.acmeServer] = acmeCredential{
			AccountKeyPEM: string(keyPEM),
			Thumbprint:    thumbprint,
		}
		state.dirty = true
	}
	return state.ACMEAccounts[settings.acmeServer], nil
}

func initACMEAccount() error {
	client, err := acme.NewClient(settings.acmeServer,
		acme.WithUserAgentSuffix("alexzorin/ngx-acme-poc"))
	if err != nil {
		return fmt.Errorf("couldn't make an ACME client: %w", err)
	}
	acmeClient = &client

	credentials, err := generateAccountKey()
	if err != nil {
		return fmt.Errorf("couldn't get/generate ACME account key: %w", err)
	}

	privkeyDER, _ := pem.Decode([]byte(credentials.AccountKeyPEM))
	privkey, err := x509.ParsePKCS8PrivateKey(privkeyDER.Bytes)
	if err != nil {
		return fmt.Errorf("couldn't parse ACME account key: %w", err)
	}

	contacts := []string{}
	if settings.acmeContactEmail != "" {
		contacts = append(contacts, "mailto:"+settings.acmeContactEmail)
	}

	log.Printf("Registering a new account with %s", settings.acmeServer)
	account, err := acmeClient.NewAccountOptions(
		(privkey).(crypto.Signer),
		acme.NewAcctOptAgreeTOS(),
		acme.NewAcctOptWithContacts(contacts...),
	)
	if err != nil {
		return fmt.Errorf("couldn't create ACME account: %w", err)
	}

	acmeAccount = &account

	return nil
}

func checkCertificate(server server) error {
	if acmeClient == nil {
		if err := initACMEAccount(); err != nil {
			return fmt.Errorf(
				"couldn't initialize ACME account while obtaining certificate for %v: %w",
				server.ServerNames, err)
		}
	}

	cert := state.existingCertificateForServer(&server)
	if cert != nil {
		needsReplacing, err := certsNeedReplacing(cert)
		if err != nil {
			// If we were unable to check whether the certificate needs replacing, then the assumption
			// is that we're not going to replace it. This is conservative and will require human
			// intervention but prevents us rapidly re-issuing certificates.
			log.Printf("could not determine if cert needs replacing for %v: %v", server.ServerNames, err)
			return nil
		} else if !needsReplacing {
			// If the certificate doesn't need replacing, then there's no work to do.
			return nil
		}
	}

	// If we're here, it means we need a new certificate for this server.
	cert, err := obtainCertificate(&server)
	if err != nil {
		return fmt.Errorf("couldn't obtain a certificate for %v: %w", server.ServerNames, err)
	}

	state.addCertificateForServer(&server, cert)

	if err := state.save(); err != nil {
		return fmt.Errorf("couldn't save state after obtaining certificate for %v: %w", server.ServerNames, err)
	}

	// Push out updates to all of the connected nginx workers as soon as we have a new certificate
	resyncCh <- struct{}{}

	return nil
}

func obtainCertificate(server *server) (*certificate, error) {
	cl := *acmeClient
	acc := *acmeAccount

	log.Printf("Creating a certificate order for %v", server.ServerNames)

	order, err := cl.NewOrderDomains(acc, server.ServerNames...)
	if err != nil {
		return nil, fmt.Errorf("failed to create order for %v: %w", server.ServerNames, err)
	}

	log.Printf("Order URL: %s", order.URL)

	for i := range order.Authorizations {
		url := order.Authorizations[i]
		authz, err := cl.FetchAuthorization(acc, url)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch auth %s: %w", url, err)
		}
		if authz.Status == "valid" {
			log.Printf("Skipping authz %s because it is already valid", url)
			continue
		}
		if authz.Status != "pending" {
			return nil, fmt.Errorf("authz %s was %s, rather than pending or valid", authz.Status, url)
		}

		chal, exists := authz.ChallengeMap[acme.ChallengeTypeHTTP01]
		if !exists {
			return nil, fmt.Errorf("authz %s did not have an HTTP-01 challenge", url)
		}
		log.Printf("Responding to challenge %s ...", chal.URL)
		chal, err = cl.UpdateChallenge(acc, chal)
		if err != nil {
			return nil, fmt.Errorf("failed to update challenge %s: %w", chal.URL, err)
		}
	}

	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		DNSNames:           server.ServerNames,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTpl, certKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)

	log.Printf("Finalizing order ...")

	order, err = cl.FinalizeOrder(acc, order, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to finalize order %s for %v: %w",
			order.URL, server.ServerNames, err)
	}

	certs, err := cl.FetchCertificates(acc, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates for %v from %s: %w",
			server.ServerNames, order.URL, err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(certKey)

	return encodeCertificate(certs, privDER), nil

}

func certsNeedReplacing(certAndKey *certificate) (bool, error) {
	chain := parseCertificateChainPEM([]byte(certAndKey.CertificateChainPEM))
	if len(chain) == 0 {
		return false, errors.New("certificate chain was empty")
	}
	cert := chain[0]

	// Check if there's less than 1/3rd of the lifetime of the certificate remaining
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	remaining := time.Until(cert.NotAfter)
	if remaining.Seconds() < lifetime.Seconds()/3 {
		log.Printf("Certificate serial %s more than 2/3 through lifetime, will renew", cert.SerialNumber)
		return true, nil
	}

	// If the certificate is ARI-capable, ask the server if it needs replacing
	if len(chain) > 1 {
		issuer := chain[1]
		renewalInfo, err := acmeClient.GetRenewalInfo(cert, issuer, crypto.SHA256)
		if err != nil && err != acme.ErrRenewalInfoNotSupported {
			log.Printf("Failed to check ARI info for cert serial %s: %v", cert.SerialNumber, err)
		} else if time.Now().After(renewalInfo.SuggestedWindow.Start) {
			log.Printf("Certificate serial %s is in the past, will renew", cert.SerialNumber)
			return true, nil
		}
	}

	// TODO: check if the certificate is revoked via OCSP

	return false, nil
}

func parseCertificateChainPEM(asPEM []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	block, rest := pem.Decode(asPEM)
	for {
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("error parsing certificate: %v", err)
			break
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	return certs
}

func encodeCertificate(chain []*x509.Certificate, keyDER []byte) *certificate {
	var chainPEM []byte
	for _, cert := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	return &certificate{
		CertificateChainPEM: string(chainPEM),
		CertificateKeyPEM:   string(keyPEM),
	}
}

func (b *updateBroker) subscribe() chan []byte {
	ch := make(chan []byte)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *updateBroker) unsubscribe(ch chan []byte) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

func (b *updateBroker) publish(msg []byte) {
	b.mu.Lock()
	for ch := range b.subs {
		select {
		case ch <- msg:
		default:
		}
	}
	b.mu.Unlock()
}
