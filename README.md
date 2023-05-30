# ngx-acme-poc

This is an experimental proof-of-concept for an ACME (RFC8555) dynamic module for nginx. Its purpose is
to automatically obtain and renew SSL certificates for HTTP servers.

## How it works

![overview](./doc/components.png)

The project includes two components:

### 1. The nginx module
The nginx module is written in C and can be found at `src/ngx_http_acme_module.c`.

![overview](./doc/module.png)

Its functions:

1. To dynamically resolve and use SSL certificates. It does this by setting a server's `ssl_certificate{,_key}` to the complex value (a.k.a variable)`data:$acme_certificate{_key}` (nginx 1.15.10+). The module then implements a runtime "get" hook for these variables, where it is able to dynamically choose a certificate to use, in the scope of an HTTP connection.

2. To launch an external ACME client. To avoid writing too much unsafe C code and to avoid highly duplicative work between nginx workers (where coordination would be a nightmare), all actual ACME client responsibilities are delegated to an external process. The nginx master process should fork this process upon launch, and worker processes interface with it via a simple HTTP API (TCP or UNIX socket, not determined).

3. To communicate with the external ACME client. 

    i. The nginx workers need to inform the ACME client of what the `server` list looks like, and what the expected certificate SANs are (combination of `server_name` and perhaps `acme_*` directives). 

    ii. The nginx workers use long-polling to receive certificate updates from the ACME client. This is a low-overhead method of communication that embeds well into the nginx event loop, and allows the ACME client to push state updates as they become available.

4. To respond to ACME HTTP challenges. Provisionally, the module will be aware of the ACME account's thumbprint, and will use a response to directly respond to ACME HTTP challenge requests. DNS challenges will be delegated to the ACME client entirely, but TLS-ALPN challenges may not be possible to implement with how nginx works today. 

### 2. The ACME client
There is an example ACME client that conforms to the design of the nginx module in `dummy-acme-client/main.go`.

Its important functions are:

1. Implement certificate acquisition, storage and renewal strategy for whatever the `server` list reported by the nginx workers is.
2. Provide a simple HTTP long-polling endpoint for nginx workers to receive certificate updates (as well as informing nginx workers of details of challenges, like key authorization strings/thumbprints).
3. Provide a simple HTTP endpoint for nginx workers to update the ACME client on the current `server` list. 

## Building
At the moment, there is a `Makefile` which is specific to my local environment. Making this portable to other environments will just involve documenting how to check out an nginx source distribution (be it from nginx.org or a Linux source deb/rpm or Homebrew) and how to use that source distribution to build the dynamic ACME module.

## Status
This is an experiment to see whether nginx's design is amenable to this kind of module and whether the module can be implemented in a way that meets the  goal of "let's do away with Certbot".

Currently, the following is implemented:

- [ ] ACME client
  - [x] Account registration
  - [x] Obtaining certificates
  - [ ] Retrying failed orders
  - [ ] Renewing certificates
  - [x] Pushing updates to workers
  - [x] Receiving worker configuration
- [ ] nginx module
  - [ ] nginx master process launches ACME client
  - [ ] ACME HTTP challenge response
  - [x] Pushes config to ACME client
  - [x] Recurringly pulls certificates from ACME client
  - [x] Dynamically uses certificates from ACME client
  - [ ] Handles reloads.
  - [ ] Allows configuring the ACME client via `acme_*` directives.
- [ ] Build
  - [ ] `Makefile` anyone can use
  - [ ] Build binaries against nginx.org source distributions
  - [ ] Build binaries against Debian/Ubuntu/EPEL source distributions.