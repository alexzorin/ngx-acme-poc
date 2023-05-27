package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"sync"
)

type server struct {
	ServerNames []string `json:"server_names"`
}

var (
	servers   []server
	serversMu sync.RWMutex
)

func main() {
	http.HandleFunc("/set-servers", handleSetServers)
	http.HandleFunc("/certificates", handleGetCertificates)
	log.Fatal(http.ListenAndServe("127.0.0.1:41934", nil))
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

	serversMu.Lock()
	servers = request.Servers
	serversMu.Unlock()
}

func handleGetCertificates(w http.ResponseWriter, r *http.Request) {
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

	serversMu.RLock()
	defer serversMu.RUnlock()

	for _, server := range servers {
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
