<h1 align="center">cert-manager</h1>
<p align="center">
  <em>Automatic SSL certificate issuance and renewal for Node.js</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/cert-manager">
    <img src="https://img.shields.io/npm/v/cert-manager?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-in%20development-yellow" alt="status">
  <img src="https://img.shields.io/github/license/colocohen/cert-manager?color=brightgreen" alt="license">
</p>


## Table of Contents
1. [What is cert-manager?](#-what-is-cert-manager)
2. [Why cert-manager?](#-why-cert-manager)
3. [Quick Start](#-quick-start)
4. [Certificate Manager](#-certificate-manager)
5. [API Reference - createOrder](#-api-reference--createorder)
6. [API Reference - manager](#-api-reference--manager)
7. [Features](#-features)
8. [Project Structure](#-project-structure)
9. [Providers](#-providers)
10. [Roadmap](#-roadmap)
11. [Contact](#-contact)
12. [License](#-license)


## ⚡ What is cert-manager?

**cert-manager** is a zero-dependency ACME client for Node.js that automates SSL/TLS certificate issuance and renewal. It implements the [ACME protocol (RFC 8555)](https://datatracker.ietf.org/doc/html/rfc8555) - the same protocol used by **Let's Encrypt**, **ZeroSSL**, and other certificate authorities - entirely in JavaScript using only `node:*` built-in modules.

Get a wildcard certificate in 10 lines of code:

```js
import ssl from 'cert-manager';

let order = ssl.createOrder({
  domain: 'example.com',
  wildcard: true,
  email: 'admin@example.com',
});

order.on('dns', (records, done) => {
  // Set DNS TXT records, then:
  done();
});

order.on('certificate', (cert) => {
  console.log(cert.cert);  // server certificate
  console.log(cert.ca);    // CA chain
  console.log(cert.key);   // private key
});

order.start();
```

That's it. No 50-line setup. No manual account creation. No CSR generation. Everything - key generation, account registration, order creation, DNS verification, challenge completion, and certificate download - is handled automatically, step by step.


## 🧠 Why cert-manager?

Existing ACME libraries for Node.js (`acme-client`, `acme`, `greenlock`) require you to manually orchestrate each step of the protocol. You create keys, then create an account, then create an order, then fetch authorizations, then respond to challenges, then finalize, then download. If anything fails, you handle it yourself.

**cert-manager** takes a different approach:

- **Simple event-driven API** - You subscribe to events (`dns`, `certificate`, `error`) instead of chaining 10 async calls. The library handles the entire ACME flow internally - errors, retries, and polling included.
- **Built-in certificate manager** - A persistent scheduler that monitors certificates, renews them automatically, and stores everything to disk. Set it up once and forget about it.
- **Zero dependencies** - Only `node:*` modules. No axios, no node-forge, no OpenSSL bindings. The entire crypto stack (JWS, CSR, ASN.1 DER encoding, ECDSA signatures) is implemented from scratch.
- **`npm install` and go** - No build tools, no native binaries, no platform-specific code.


## 📦 Quick Start

```bash
npm install cert-manager
```

### Single certificate

```js
import ssl from 'cert-manager';

let order = ssl.createOrder({
  domain: 'example.com',
  wildcard: true,
  email: 'admin@example.com',
  staging: true, // use Let's Encrypt staging for testing
});

order.on('dns', (records, done) => {
  // records = [{ type: 'TXT', name: '_acme-challenge.example.com', value: '...' }, ...]
  // Set these DNS records at your DNS provider, then call done()
  console.log('Set DNS records:', records);
  done();
});

order.on('certificate', (cert) => {
  // cert.cert   - server certificate (PEM)
  // cert.ca     - CA chain (array of PEMs)
  // cert.key    - private key (PEM)
  // cert.csr    - certificate signing request (PEM)
  // cert.expiresAt - Date object
  console.log('Certificate issued! Expires:', cert.expiresAt);
});

order.on('error', (err, step) => {
  console.error('Error at', step, ':', err.message);
});

order.start();
```

### CommonJS

```js
const ssl = require('cert-manager');

let order = ssl.createOrder({
  domain: 'example.com',
  email: 'admin@example.com',
});
// ... same API
```

### DNS Provider Integration

The `dns` event gives you full control over how DNS records are set. Use any DNS provider API you want:

**Cloudflare:**
```js
order.on('dns', (records, done) => {
  let pending = records.length;
  records.forEach((record) => {
    fetch(`https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${CF_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'TXT', name: record.name, content: record.value, ttl: 120 }),
    }).then(() => { if (--pending <= 0) done(); });
  });
});
```

**AWS Route53:**
```js
order.on('dns', (records, done) => {
  let changes = records.map((r) => ({
    Action: 'UPSERT',
    ResourceRecordSet: { Name: r.name, Type: 'TXT', TTL: 120, ResourceRecords: [{ Value: `"${r.value}"` }] }
  }));
  route53.changeResourceRecordSets({
    HostedZoneId: ZONE_ID,
    ChangeBatch: { Changes: changes },
  }, () => done());
});
```

Any provider that has an API works the same way - you get `records`, call the API, call `done()`.


## 🔄 Certificate Manager

For production environments, use the **manager** to handle automatic renewal for multiple domains:

```js
import ssl from 'cert-manager';

let mgr = ssl.manager({
  dir: './certs',
  email: 'admin@example.com',
});

mgr.add('example.com', { wildcard: true });
mgr.add('other.com');

mgr.on('dns', (domain, records, done) => {
  console.log(domain, 'needs DNS records:', records);
  // Set DNS records, then:
  done();
});

mgr.on('certificate', (domain, cert) => {
  console.log(domain, 'certificate ready!');
  // Install cert on your server
});

mgr.on('renewing', (domain, daysLeft) => {
  console.log(domain, 'renewing, days left:', daysLeft);
});

mgr.on('error', (domain, err) => {
  console.error(domain, 'failed:', err.message);
});

mgr.start();
```

The manager creates this directory structure:

```
./certs/
├── account.json            - shared ACME account key
├── certificates.csv        - domain status table
├── example.com.json        - certificate + private key
└── other.com.json          - certificate + private key
```

On process restart, call `mgr.start()` - it reads the CSV and picks up where it left off. No need to call `add()` again.


## 📘 API Reference - createOrder

### Options

```js
ssl.createOrder({
  domain: 'example.com',       // required
  email: 'admin@example.com',  // required

  wildcard: false,              // also issue *.example.com
  altNames: [],                 // additional SANs
  provider: 'letsencrypt',     // 'letsencrypt' or 'zerossl'
  staging: false,               // use staging environment for testing

  // Keys (auto-generated if not provided)
  accountKey: null,             // PEM - reuse existing account
  privateKey: null,             // PEM - reuse existing key
  csr: null,                    // PEM - provide your own CSR

  // EAB (for ZeroSSL)
  eab: null,                    // { kid: '...', hmacKey: '...' }

  // CSR extra fields
  csrFields: {},                // { country, state, locality, organization, organizationUnit }

  // Behavior
  preflight: true,              // check CAA records before starting
  autoVerify: true,             // automatically poll DNS for challenge records
  autoStart: false,             // start immediately without calling .start()
});
```

### Events

| Event | Callback | Description |
|---|---|---|
| `dns` | `(records, done)` | DNS records to set. Call `done()` when ready. |
| `certificate` | `(cert)` | Certificate issued. `cert.cert`, `cert.ca`, `cert.key`, `cert.csr`, `cert.expiresAt` |
| `account` | `(account)` | Account created. `account.url`, `account.key` |
| `verify` | `(info)` | DNS verification progress. `info.attempt`, `info.found`, `info.expected` |
| `validating` | `(info)` | CA validation progress. `info.attempt`, `info.statuses` |
| `completing` | `(info)` | Challenge submission results. `info.results` |
| `error` | `(err, step)` | Error at a specific step |

### Methods

| Method | Description |
|---|---|
| `order.start()` | Begin the certificate issuance flow |
| `order.abort()` | Cancel everything, clear all timers |
| `order.getState()` | Current state name |
| `order.getDomain()` | Domain name |
| `order.getAccountKey()` | Account key PEM |
| `order.getPrivateKey()` | Private key PEM |
| `order.getCsr()` | CSR (DER buffer or PEM) |

## 📘 API Reference - manager

### Options

```js
ssl.manager({
  dir: './certs',          // required - where to store files
  email: 'admin@example.com',   // required
  provider: 'letsencrypt',
  staging: false,
  eab: null,                     // { kid, hmacKey } for ZeroSSL
});
```

### Methods

| Method | Description |
|---|---|
| `mgr.add(domain, opts)` | Add domain. Ignored if already exists. `opts: { wildcard, email }` |
| `mgr.remove(domain)` | Remove domain from CSV + delete JSON |
| `mgr.get(domain, callback)` | Get certificate + metadata from JSON file |
| `mgr.list(callback)` | List all domains from CSV |
| `mgr.renewNow(domain)` | Force immediate renewal |
| `mgr.status()` | Domain currently being renewed, or `null` |
| `mgr.start()` | Start the manager - reads CSV, begins processing |
| `mgr.stop()` | Stop timer, abort current order |

### Events

| Event | Callback | Description |
|---|---|---|
| `dns` | `(domain, records, done)` | DNS records needed. Call `done()` when set. |
| `certificate` | `(domain, cert)` | Certificate issued or renewed |
| `renewing` | `(domain, daysLeft)` | Renewal started |
| `error` | `(domain, err)` | Error during renewal |

### Built-in protections

- **Serial processing** - one domain at a time, never parallel
- **Retry throttle** - minimum 4 hours between attempts per domain
- **Timeout** - 10 minutes per domain, then abort and move on
- **Priority** - domains never attempted are processed first, then oldest attempts
- **Duplicate ignore** - `add()` silently skips existing domains
- **Renewal window** - 7 days before expiry


## ✨ Features

- Full ACME RFC 8555 implementation (DNS-01 challenge)
- Event-driven API - no callback hell, no manual orchestration
- Zero dependencies - only `node:*` built-in modules
- Let's Encrypt and ZeroSSL support (any ACME-compatible CA)
- External Account Binding (EAB) for ZeroSSL
- Wildcard certificates (`*.example.com`)
- Certificate + CA chain separation
- CAA record preflight check
- DNS verification with fallback resolvers (8.8.8.8, 1.1.1.1)
- Automatic key generation (ECDSA P-256 or RSA)
- Custom CSR fields (country, organization, etc.)
- badNonce auto-retry
- Certificate manager with persistent storage (CSV + JSON)
- Automatic renewal with configurable schedule
- ESM + CommonJS + TypeScript support


## 📁 Project Structure

```
cert-manager/
├── index.js                 - Public API (ESM)
├── index.cjs                - CommonJS wrapper
├── index.d.ts               - TypeScript definitions
├── package.json
└── src/
    ├── order.js              - Certificate order engine
    ├── manager.js            - Certificate manager with auto-renewal
    ├── crypto.js             - Key generation, CSR, JWS, EAB signing
    ├── http.js               - ACME HTTP client with JWS authentication
    ├── verify.js             - DNS TXT verification + CAA check
    ├── asn1.js               - DER encoding for CSR generation
    └── providers.js          - CA directory URLs (Let's Encrypt, ZeroSSL)
```


## 🌐 Providers

### Let's Encrypt (default)

```js
ssl.createOrder({
  domain: 'example.com',
  email: 'admin@example.com',
  provider: 'letsencrypt',
});
```

### ZeroSSL

```js
ssl.createOrder({
  domain: 'example.com',
  email: 'admin@example.com',
  provider: 'zerossl',
  eab: {
    kid: 'YOUR_EAB_KID',
    hmacKey: 'YOUR_EAB_HMAC_KEY',
  },
});
```


## 🛣 Roadmap

### ✅ Done
- ACME RFC 8555 - full protocol implementation
- DNS-01 challenge with automatic verification
- Event-driven API with automatic flow management
- Let's Encrypt + ZeroSSL support
- EAB (External Account Binding)
- Wildcard certificates
- Certificate + CA chain separation
- CAA record preflight check
- CSR with custom fields
- Certificate manager with auto-renewal
- Persistent storage (CSV + JSON)
- ESM + CommonJS + TypeScript support

### ⏳ Planned
- Certificate revocation (RFC 8555 §7.6)
- DNS provider API integration (Cloudflare, Route53)
- Account key rollover
- Custom ACME directory URL
- OCSP stapling helper

_Community contributions are welcome! Please ⭐ star the repo to follow progress._


## 🙏 Sponsors

cert-manager is an evenings-and-weekends project.  
Support development via **GitHub Sponsors** or simply share the project.


## 📜 License

**Apache License 2.0**

```
Copyright © 2025 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```