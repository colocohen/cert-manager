<h1 align="center">cert-manager</h1>
<p align="center">
  <em>Automatic SSL certificate issuance and renewal for Node.js — domains and IP addresses</em>
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
4. [IP Address Certificates](#-ip-address-certificates)
5. [Challenge Types](#-challenge-types)
6. [tls-alpn-01 with lemon-tls](#-tls-alpn-01-with-lemon-tls)
7. [Certificate Manager](#-certificate-manager)
8. [ARI - Smart Renewal Timing](#-ari---smart-renewal-timing)
9. [External signers (HSM, KMS, remote signing)](#-external-signers-hsm-kms-remote-signing)
10. [EST - private CAs (RFC 7030)](#-est---private-cas-rfc-7030)
11. [API Reference - createOrder](#-api-reference---createorder)
12. [API Reference - manager](#-api-reference---manager)
13. [Features](#-features)
14. [Project Structure](#-project-structure)
15. [Providers](#-providers)
16. [Testing](#-testing)
17. [Roadmap](#-roadmap)
18. [License](#-license)


## ⚡ What is cert-manager?

**cert-manager** is an ACME client for Node.js that automates SSL/TLS certificate issuance and renewal — for **domain names and IP addresses** (IPv4 and IPv6). It implements the [ACME protocol (RFC 8555)](https://datatracker.ietf.org/doc/html/rfc8555) - the same protocol used by **Let's Encrypt**, **ZeroSSL**, and other certificate authorities - entirely in JavaScript, with no native code.

Beyond the core protocol, it implements the extensions that modern issuance requires:

| Spec | What it enables |
|---|---|
| [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) | Core ACME protocol |
| [RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737) | `tls-alpn-01` challenge (validation over port 443) |
| [RFC 8738](https://datatracker.ietf.org/doc/html/rfc8738) | Certificates for IP addresses |
| [RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773) | ARI - CA-guided renewal timing + rate-limit exemption |
| [draft-ietf-acme-profiles](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/) | Certificate profiles (e.g. Let's Encrypt `shortlived`) |
| [RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030) | EST - the same orders and manager against private CAs that speak EST |

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

Or a certificate for a bare IP address — no domain required:

```js
let order = ssl.createOrder({
  domain: '203.0.113.10',
  email: 'admin@example.com',
  challengeType: 'http-01',
});
```

That's it. No 50-line setup. No manual account creation. No CSR generation. Everything - key generation, account registration, order creation, challenge handling, verification, and certificate download - is handled automatically, step by step.


## 🧠 Why cert-manager?

Existing ACME libraries for Node.js (`acme-client`, `acme`, `greenlock`) require you to manually orchestrate each step of the protocol. You create keys, then create an account, then create an order, then fetch authorizations, then respond to challenges, then finalize, then download. If anything fails, you handle it yourself.

**cert-manager** takes a different approach:

- **Simple event-driven API** - You subscribe to events (`dns`, `http`, `tls-alpn`, `certificate`, `error`) instead of chaining 10 async calls. The library handles the entire ACME flow internally - errors, retries, and polling included.
- **IP address certificates** - First-class support for IPv4 and IPv6 identifiers (RFC 8738), including the Let's Encrypt `shortlived` profile they require - selected automatically.
- **Built-in certificate manager** - A persistent scheduler that monitors certificates, renews them automatically (ARI-guided), and stores everything to disk. Set it up once and forget about it.
- **Keys that never leave their home** - The account key and the certificate key can be a PEM string, or an [external signer](#-external-signers-hsm-kms-remote-signing): an HSM, a cloud KMS, a remote or threshold signing service. The library then sees only the public key, and handles a signer that is slow, refuses, or does not answer.
- **`npm install` and go** - No build tools, no native binaries, no platform-specific code.


## 📦 Quick Start

```bash
npm install cert-manager
```

### Single certificate (domain, dns-01)

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


## 🌍 IP Address Certificates

Let's Encrypt issues certificates for IP addresses (generally available since January 2026). cert-manager supports this end to end - IPv4, IPv6, and both in one certificate:

```js
let order = ssl.createOrder({
  domain: '203.0.113.10',              // IPv4 or IPv6 — detected automatically
  altNames: ['2001:db8::1'],           // more addresses → more iPAddress SANs
  email: 'admin@example.com',
  challengeType: 'http-01',            // or 'tls-alpn-01' — dns-01 is forbidden for IPs
});

order.on('http', (records, done) => {
  // Serve records[i].keyAuthorization as plain text at
  //   http://<ip>:80{records[i].path}
  // then call done()
});

order.on('certificate', (cert) => {
  // Valid for 160 hours (~6.7 days) — see "Rules of the road" below
});

order.start();
```

**What the library handles for you:**

- The identifier is sent as `{ type: 'ip' }` instead of `{ type: 'dns' }` (RFC 8738)
- The CSR encodes the address as raw `iPAddress` SAN bytes (4 for IPv4, 16 for IPv6) — not text
- The `shortlived` certificate profile is selected automatically (a Let's Encrypt policy requirement for IP certs), and validated against the CA's advertised profiles before ordering
- No Common Name is placed in the subject (IP certs have none)
- The CAA preflight is skipped (CAA is a DNS record — it doesn't exist for IPs)
- `dns-01` is rejected locally with a clear error, instead of an opaque CA failure

**Rules of the road:**

1. **IP certificates are short-lived: 160 hours (~6.7 days).** This is CA policy, not a library choice. Use the [manager](#-certificate-manager) — it adapts its renewal schedule to the real lifetime (renews after ~4.4 days).
2. **Each identifier is validated separately.** The CA connects to every address in the order. If you include an IPv6 address, port 80/443 must be reachable over IPv6 (listen on `'::'` for dual-stack).
3. **No wildcards** with IP addresses.
4. **Mixing a domain and IPs in one certificate works**, but the whole order then uses one challenge type (dns-01 is off the table) and the whole certificate is short-lived. Usually two separate certificates serve you better.

### Self-verification and NAT

Before submitting challenges to the CA, cert-manager verifies them itself (`autoVerify`). For `http-01` this means fetching `http://<ip>/.well-known/acme-challenge/<token>` — which can fail on home networks where the router doesn't support NAT hairpinning (reaching your own public IP from inside), even though external access is fine. Two escape hatches:

```js
// per-call: skip the self-check when you've verified reachability yourself
order.on('http', (records, done) => {
  serveChallenges(records);
  done({ skipVerify: true });
});

// or per-order:
ssl.createOrder({ ..., autoVerify: false });
```

`tls-alpn-01` has no self-check at all — `done()` goes straight to the CA.


## 🔀 Challenge Types

ACME defines several ways to prove control over an identifier. Pick one per order with `challengeType`:

| challengeType | Proves control via | Port | Domains | IPs | Wildcard |
|---|---|---|---|---|---|
| `'dns-01'` (default) | TXT record in DNS | — | ✅ | ❌ (RFC 8738) | ✅ (only option) |
| `'http-01'` | File served over HTTP | 80 | ✅ | ✅ | ❌ |
| `'tls-alpn-01'` | Special cert in a TLS handshake | 443 | ✅ | ✅ | ❌ |

Each type has its own event carrying exactly what you need:

```js
// dns-01 → 'dns' event: TXT records to publish
order.on('dns', (records, done) => { ... });

// http-01 → 'http' event: token + keyAuthorization + path to serve
order.on('http', (records, done) => { ... });

// tls-alpn-01 → 'tls-alpn' event: a ready-made challenge certificate
order.on('tls-alpn', (records, done) => { ... });
```

Which to choose: `dns-01` when you control DNS via API (and always for wildcards); `http-01` when port 80 is reachable; `tls-alpn-01` when only 443 is open or you want validation to stay inside the TLS layer. If a router or firewall dictates which port is open, let the code that knows (e.g. a port-mapping layer) pick the type — the library will fail fast with a clear error on invalid combinations.


## 🍋 tls-alpn-01 with lemon-tls

For `tls-alpn-01`, the CA connects to port 443 offering the ALPN protocol `acme-tls/1` and SNI set to the identifier — or, for IP addresses, its reverse-DNS name (`4.3.2.81.in-addr.arpa`), since SNI can't carry IP literals (RFC 8738).

cert-manager builds the challenge certificate for you (single-entry SAN, critical `acmeIdentifier` extension with the SHA-256 digest — all the RFC 8737 details handled). Serving it takes a few lines with [lemon-tls](https://github.com/colocohen/lemon-tls):

```js
import ssl from 'cert-manager';
import lemon from 'lemon-tls';

let challenge_ctxs = {};   // sniName → SecureContext
let site_ctx = null;       // your normal site certificate

let server = lemon.createServer({
  // 'acme-tls/1' must be in the list so the handshake can negotiate it.
  // Browsers never offer it, so it changes nothing for normal traffic.
  ALPNProtocols: ['h2', 'http/1.1', 'acme-tls/1'],
  SNICallback: function(servername, cb) {
    cb(null, challenge_ctxs[servername] || site_ctx);
  },
});
server.listen(443);

let order = ssl.createOrder({
  domain: '203.0.113.10',
  email: 'admin@example.com',
  challengeType: 'tls-alpn-01',
});

order.on('tls-alpn', function(records, done) {
  for (let r of records) {
    challenge_ctxs[r.sniName] = lemon.createSecureContext({ cert: r.cert, key: r.key });
  }
  done();
});

order.on('certificate', function(cert) {
  challenge_ctxs = {};
  site_ctx = lemon.createSecureContext({ cert: cert.cert + cert.ca.join(''), key: cert.key });
});

order.start();
```

For IP identifiers the incoming challenge SNI (the `.arpa` name) never collides with real traffic, so plain SNI routing is all you need. Advanced consumers can also build challenge certs directly via `ssl.crypto.createAlpnCertificate(identifier, keyAuthorization)`.


## 🔄 Certificate Manager

For production environments, use the **manager** to handle automatic renewal for multiple domains and IPs:

```js
import ssl from 'cert-manager';

let mgr = ssl.manager({
  dir: './certs',
  email: 'admin@example.com',
});

mgr.add('example.com', { wildcard: true });
mgr.add('other.com');
mgr.add('203.0.113.10', { challengeType: 'http-01' });
mgr.add('2001:db8::1',  { challengeType: 'tls-alpn-01' });

mgr.on('dns', (domain, records, done) => {
  // dns-01 domains: set DNS records, then done()
  done();
});

mgr.on('http', (domain, records, done) => {
  // http-01 identifiers: serve the challenge files, then done()
  done();
});

mgr.on('tls-alpn', (domain, records, done) => {
  // tls-alpn-01 identifiers: load records[i].cert/key into your TLS server
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
├── account.json            - shared ACME account: its key and URL (or URL + public JWK, with accountKey)
├── certificates.csv        - domain status table
├── example.com.json        - certificate + private key + per-domain settings
└── 2001_db8__1.json        - (IPv6 filenames are sanitized; the CSV keeps the raw address)
```

On process restart, call `mgr.start()` - it reads the CSV and picks up where it left off. No need to call `add()` again.

### Renewal timing that adapts to the certificate

The renewal point is derived from the certificate's **actual** lifetime, so 90-day and 160-hour certificates coexist in one manager:

- 90-day certificate → renews 7 days before expiry (day 83), same as always
- 160-hour certificate → renews after ~4.4 days (margin capped at ⅓ of the lifetime)
- Within 48 hours of expiry, failed attempts retry every 30 minutes instead of every 4 hours
- Timestamps are stored with full precision (day granularity is useless for 6-day certs)

And when the CA supports ARI, its recommendation takes over — see the next section.


## 📡 ARI - Smart Renewal Timing

**ARI (ACME Renewal Information, [RFC 9773](https://datatracker.ietf.org/doc/html/rfc9773))** lets the manager ask the CA when *it* recommends renewing each certificate, instead of guessing locally. The manager does this automatically — no configuration needed:

1. Periodically (respecting the CA's `Retry-After`, ~6h) it queries `GET {renewalInfo}/{certId}` — an unauthenticated endpoint — for each active certificate.
2. It picks a uniformly random moment inside the CA's `suggestedWindow` (spreading load, per the RFC) and schedules the renewal there. If the window is already in the past — e.g. the CA is signaling an urgent replacement before a mass revocation — renewal happens immediately.
3. Renewal orders include the `replaces` field identifying the outgoing certificate. **Renewals inside the ARI window with `replaces` are exempt from Let's Encrypt rate limits** — significant when short-lived certs renew twice a week.
4. If the CA rejects the `replaces` value (e.g. the old cert was already replaced), the order automatically retries once without it — ARI can never block a renewal.

Because the manager is a long-running process with its own timer (not a cron job), it can honor short `Retry-After` intervals and react to emergency signals within hours — something scheduled-run clients structurally can't.

Disable with `ssl.manager({ ..., ari: false })`. Advanced consumers can compute identifiers directly via `ssl.crypto.getAriCertId(certPem)`.


## 🔐 External signers (HSM, KMS, remote signing)

Wherever cert-manager takes a private key - the ACME **account key** and the **certificate key** - it also takes a **signer**: an object that can sign, while the key itself stays where it is (an HSM, a cloud KMS, a remote or threshold signing service). The library sees only the public key.

```js
let order = ssl.createOrder({
  domain: 'example.com',
  email: 'admin@example.com',

  accountKey: {
    publicKey: accountPublicKeyPem,      // SPKI PEM or DER, or a public JWK
    algorithm: 'ES256',                  // optional - checked against the key
    signatureFormat: 'raw',              // ECDSA: what sign() returns - 'raw' (r||s) or 'der'
    sign: function (bytes, cb) {         // cb(err, signature)
      remoteSigner.sign('acme-account', bytes, cb);
    },
  },
});

order.on('error', (err, step) => {
  if (err.code === 'SIGN_REJECTED') { /* the signer said no - err.cause is its own error */ }
  if (err.code === 'SIGN_TIMEOUT')  { /* no answer in signTimeout, after retries */ }
});
```

That is the whole change for the caller: everything else - challenges, events, the manager - works as before.

### What the signer is given, and must return

- **`bytes`** is the complete message to sign - not a hash of it. For the account key it is the JWS signing input of one ACME request (`base64url(header) "." base64url(payload)`); for the certificate key, the CSR's `CertificationRequestInfo`. The signer hashes as its algorithm says (SHA-256 for ES256 and RS256, SHA-384 for ES384).
- **The signature** comes back as bytes (`Uint8Array` / `Buffer`). For ECDSA, say which form with `signatureFormat`: ACME's JWS needs raw `r||s` and X.509 needs DER, and the library converts whichever it gets. Check what yours returns - PKCS#11 (`CKM_ECDSA`) gives `r||s`, cloud KMS APIs usually give DER. Default: `'raw'` for `accountKey`, `'der'` for `privateKey`.
- **Every signature is verified** against `publicKey` before anything is sent. A wrong key or a wrong `signatureFormat` fails at once with `SIGN_INVALID`, instead of coming back from the CA as an opaque `badSignature`.

### Keys

| | Account key (`accountKey`) | Certificate key (`privateKey`) |
|---|---|---|
| ECDSA P-256 / P-384 | ✅ ES256 / ES384 | ✅ |
| RSA ≥ 2048 | ✅ RS256 | ✅ |
| Ed25519 | ❌ not accepted by Let's Encrypt - refused up front | ❌ |
| Signs | every ACME request - tens per order | the CSR - once per certificate |

A key that cannot work - an unsupported type, an `algorithm` that does not match the key, a *private* JWK handed over as `publicKey` - is refused when the order starts, with `step === 'options'`, before any request.

### Slow, refusing, or silent signers

| Situation | What happens | `err.code` |
|---|---|---|
| The signer takes a while | The flow waits, up to `signTimeout` per signature (default 60 s) | — |
| It does not answer in time | Retried `signRetries` times (default 2), with backoff; a late answer is ignored | `SIGN_TIMEOUT` |
| It answers with an error | Not retried - a refusal is a decision. Unless the error has `retryable: true` | `SIGN_REJECTED` |
| It answers with something that is not a valid signature by this key | Stopped before sending | `SIGN_INVALID` |

The error's `step` says where in the flow it happened (`'account'`, `'order'`, `'csr'`, ...). When the CA answers `badNonce`, the request is signed **again** over the new nonce - one more signature, which is why those retries are bounded too.

For a signer that applies a policy: the bytes describe themselves. The JWS protected header holds the request's `url` and `nonce`, and the payload is readable JSON, so a signing service can decode them and allow only requests to the CA's own URLs.

### The certificate key in an HSM

```js
ssl.createOrder({
  domain: 'example.com',
  email: 'admin@example.com',
  privateKey: { publicKey: hsmPublicKeyPem, signatureFormat: 'raw', sign: hsmSign },
});
```

The CSR is built and signed through the signer; the issued certificate carries the HSM's public key. The `certificate` event then gives `key: null` - there is no private key to hand back. The CSR is built beside the ACME requests, so a slow signature only delays the final step that needs it.

### With the manager

```js
let mgr = ssl.manager({
  dir: './certs',
  email: 'admin@example.com',
  accountKey: accountSigner,                       // a signer, or a PEM string
  certKey: function (domain, cb) {                 // optional, per domain
    cb(null, hsmSignerFor(domain));                //   or cb(null, null) for a fresh key
  },
  orderTimeout: 30 * 60 * 1000,                    // when signing may wait for a person
});
```

- **`account.json` keeps only `{ url, jwk }`** when `accountKey` is given - no private key is written. The URL is reused only if it was registered with the same key (same JWK thumbprint). A file left by another key - for example the generated key of an earlier setup - is renamed to `account.json.<time>.bak`, never overwritten, and a new account is registered; the `error` event says so.
- Certificates whose key comes from `certKey` are stored with `key: null`.
- Without `accountKey`, nothing changes: a key is generated and kept in `account.json`, as before.

### The crypto helpers

`ssl.crypto.signJws` and `ssl.crypto.createCsr` keep their synchronous PEM form. Add a callback as the last argument and they also take a signer:

```js
ssl.crypto.createCsr({ commonName: 'example.com' }, signer, function (err, der) { /* ... */ });
ssl.crypto.signJws(payload, header, signer, function (err, jws) { /* ... */ });
```


## 🏢 EST - private CAs (RFC 7030)

Inside an organization, the CA is often not an ACME CA: EJBCA, Cisco, many enterprise PKIs - and [ca-manager](https://github.com/colocohen/ca-manager) - speak **EST**. The same `createOrder` and the same manager talk to them; only `provider` changes:

```js
let order = ssl.createOrder({
  domain: 'db.internal.example.com',
  provider: { est: 'https://est.example.com', ca: estServerRootPem },   // label: 'client' for a CA label
  auth: { username: 'svc-db', password: process.env.EST_PASSWORD },     // or { clientCert, clientKey }
});

order.on('pending', (info) => { /* { retryAfter, attempt } - the CA is still deciding (an approval) */ });
order.on('certificate', (cert) => {
  // cert.cert, cert.key, cert.csr, cert.expiresAt - as with ACME
  // cert.ca      - the chain to send with it
  // cert.cacerts - every CA certificate the server gave, for trust stores
  // cert.via     - 'simpleenroll' or 'simplereenroll'
});
order.on('error', (err, step) => { /* err.code 'EST_UNAUTHORIZED' / 'EST_FORBIDDEN', err.status */ });
order.start();
```

There are no challenges: the client proves who it is, with a password (HTTP Basic), a certificate it already holds (TLS client authentication - a device's factory certificate, say), or both. What only ACME has - `challengeType`, `eab`, `accountKey`, `profile`, `replaces`, `staging` - is refused by name, not ignored.

**Renewing** goes with the current certificate: `renew: { cert, key }` sends `simplereenroll`, authenticated by that certificate over TLS. If the CA refuses it (revoked, policy changed), and `auth` is given, the order enrolls anew with `auth`. A key held by a signer cannot authenticate TLS from Node, so then the renewal goes straight to `auth`; the CSR is still signed by the signer.

**What comes back is checked** before `certificate` fires: the certificate must be for the key in the CSR, and issued by one of the CA certificates the server gave (`cacerts`). The chain (`cert.ca`) runs from the issuer up and stops before a self-signed root; after the CA [rotated its root](https://github.com/colocohen/ca-manager#rotating-the-ca-key), it is the cross certificate, so clients that trust only the old root still verify.

**Approvals that take time**: a CA that answers 202 is asked again after its `Retry-After`, with a `pending` event each time, up to `pendingTimeout` (10 minutes by default). ACME orders give the same `pending` event while the CA is `processing`.

**The manager** works the same way - no email, no account, no ARI:

```js
let mgr = ssl.manager({
  dir: './certs',
  provider: { est: 'https://est.example.com', ca: estServerRootPem },
  auth: { username: 'svc', password: process.env.EST_PASSWORD },
});
mgr.add('db.internal.example.com');
mgr.on('certificate', (domain, cert) => { /* install it */ });
mgr.start();
```

Renewals go with the certificate on disk (`simplereenroll`), and fall back to `auth`. The renewal timing, the files and the CSV are as with ACME.


## 📘 API Reference - createOrder

### Options

```js
ssl.createOrder({
  domain: 'example.com',        // required — domain, IPv4, or IPv6 (auto-detected)
  email: 'admin@example.com',   // required

  wildcard: false,              // also issue *.example.com (dns-01 + domains only)
  altNames: [],                 // additional SANs — domains and/or IPs
  provider: 'letsencrypt',      // 'letsencrypt', 'zerossl', { acme: directoryUrl },
                                // or { est: url, label, ca } - see Providers, EST
  staging: false,               // use staging environment for testing

  // Challenge & profile
  challengeType: 'dns-01',      // 'dns-01' | 'http-01' | 'tls-alpn-01'
                                // (IP identifiers require http-01 or tls-alpn-01)
  profile: null,                // ACME certificate profile, e.g. 'shortlived'.
                                // Auto-set for IP orders; validated against the
                                // CA's advertised profiles before ordering.
  replaces: null,               // ARI certId of the cert this order replaces
                                // (the manager fills this in automatically)

  // Keys (auto-generated if not provided) - a PEM string, or a signer
  // { publicKey, sign, algorithm, signatureFormat } (see External signers)
  accountKey: null,             // reuse an existing account key
  accountUrl: null,             // its account URL - skips newAccount
  privateKey: null,             // the certificate's key
  csr: null,                    // PEM or DER - provide your own CSR
  signTimeout: 60000,           // ms for one signature by a signer
  signRetries: 2,               // after a timeout, or an error marked retryable

  // EAB (for ZeroSSL)
  eab: null,                    // { kid: '...', hmacKey: '...' }

  // CSR extra fields
  csrFields: {},                // { country, state, locality, organization, organizationUnit }

  // Behavior
  preflight: true,              // check CAA records before starting (skipped for IPs)
  autoVerify: true,             // self-verify challenges before submitting to the CA
  autoStart: false,             // start immediately without calling .start()
});
```

### Events

| Event | Callback | Description |
|---|---|---|
| `dns` | `(records, done)` | dns-01: TXT records to set. Call `done()` when ready. |
| `http` | `(records, done)` | http-01: `{ identifier, token, keyAuthorization, path }` per challenge. Serve `keyAuthorization` at `http://<identifier>:80<path>`, then `done()`. |
| `tls-alpn` | `(records, done)` | tls-alpn-01: `{ identifier, sniName, alpnProtocol, cert, key, keyAuthorization, keyAuthorizationDigest }`. Serve `cert`/`key` on :443 for SNI `sniName`, then `done()`. |
| `certificate` | `(cert)` | Certificate issued. `cert.cert`, `cert.ca`, `cert.key` (`null` when `privateKey` is a signer), `cert.csr`, `cert.expiresAt` |
| `account` | `(account)` | Account created. `account.url`, `account.key` (the PEM, or the signer) |
| `verify` | `(info)` | Self-verification progress. `info.attempt`, `info.found`, `info.expected` |
| `validating` | `(info)` | CA validation progress. `info.attempt`, `info.statuses` |
| `completing` | `(info)` | Challenge submission results. `info.results` |
| `pending` | `(info)` | The CA is still deciding: `{ retryAfter, attempt }` - ACME `processing`, EST 202 |
| `error` | `(err, step)` | Error at a specific step. Signing failures carry `err.code`: `SIGN_REJECTED`, `SIGN_TIMEOUT`, `SIGN_INVALID` |

`done(opts)` accepts `{ skipVerify: true }` to bypass self-verification (useful behind NAT without hairpinning). `done.retry()` restarts verification after fixing records.

### Methods

| Method | Description |
|---|---|
| `order.start()` | Begin the certificate issuance flow |
| `order.abort()` | Cancel everything, clear all timers |
| `order.getState()` | Current state name |
| `order.getDomain()` | Domain / IP |
| `order.getProfile()` | Effective certificate profile (may be auto-set) |
| `order.getChallengeType()` | Effective challenge type |
| `order.getAccountKey()` | Account key - PEM, or the signer given |
| `order.getPrivateKey()` | Private key - PEM, or the signer given |
| `order.getCsr()` | CSR (DER buffer or PEM) |

## 📘 API Reference - manager

### Options

```js
ssl.manager({
  dir: './certs',               // required - where to store files
  email: 'admin@example.com',   // required
  provider: 'letsencrypt',
  staging: false,
  eab: null,                    // { kid, hmacKey } for ZeroSSL
  ari: true,                    // ARI renewal guidance (RFC 9773)
  renewBeforeDays: 7,           // renewal margin — capped at ⅓ of the cert's lifetime

  accountKey: null,             // PEM or signer - then account.json holds no private key
  certKey: null,                // function (domain, cb) → cb(null, signerOrPem | null)
  orderTimeout: 600000,         // one whole issuance, in ms
  signTimeout: 60000,           // passed to each order
  signRetries: 2,
});
```

### Methods

| Method | Description |
|---|---|
| `mgr.add(domain, opts)` | Add domain or IP. Ignored if already exists. `opts: { wildcard, email, challengeType, profile, autoVerify }` |
| `mgr.remove(domain)` | Remove domain from CSV + delete JSON |
| `mgr.get(domain, callback)` | Get certificate + metadata from JSON file |
| `mgr.list(callback)` | List all domains from CSV |
| `mgr.store(domain, { cert, key, ca }, callback)` | Keep a certificate issued elsewhere (PEM); never renewed here. Refused unless the key is the certificate's, it covers `domain` (its subjectAltName - a common name alone covers nothing, as in browsers), it has not expired, and `ca` (an array of PEM, or one bundle) decodes. An older certificate does not replace a newer one. `callback(err, { stored, expiresAt } \| { stored: false, reason })` |
| `mgr.renewNow(domain)` | Force immediate renewal |
| `mgr.status()` | Domain currently being renewed, or `null` |
| `mgr.start()` | Start the manager - reads CSV, begins processing |
| `mgr.stop()` | Stop timer, abort current order |

### Events

| Event | Callback | Description |
|---|---|---|
| `dns` | `(domain, records, done)` | dns-01 records needed. Call `done()` when set. |
| `http` | `(domain, records, done)` | http-01 challenges to serve. Call `done()` when serving. |
| `tls-alpn` | `(domain, records, done)` | tls-alpn-01 certs to install. Call `done()` when live. |
| `certificate` | `(domain, cert)` | Certificate issued or renewed |
| `renewing` | `(domain, daysLeft)` | Renewal started |
| `pending` | `(domain, info)` | The CA is still deciding (an approval) |
| `error` | `(domain, err)` | Error during renewal |

### Built-in protections

- **Serial processing** - one domain at a time, never parallel
- **Retry throttle** - minimum 4 hours between attempts per domain (30 minutes within 48h of expiry)
- **Timeout** - `orderTimeout` per domain (10 minutes by default), then abort and move on
- **Priority** - domains never attempted are processed first, then oldest attempts
- **Duplicate ignore** - `add()` silently skips existing domains
- **Renewal window** - derived from the real certificate lifetime, refined by ARI
- **Atomic writes** - the CSV is written via temp-file + rename; a crash can't corrupt it
- **Private files** - `account.json` and each certificate's JSON are written readable by the owner only (`0600`)


## ✨ Features

- Full ACME RFC 8555 implementation
- **All three challenge types: dns-01, http-01, tls-alpn-01** (RFC 8737)
- **IP address certificates** - IPv4 + IPv6, single or mixed (RFC 8738)
- **ACME certificate profiles** (draft-ietf-acme-profiles) with local validation, `shortlived` auto-selection for IPs
- **ARI** (RFC 9773) - CA-guided renewal windows, `replaces` on renewals, rate-limit exemption
- **tls-alpn-01 challenge certificates built in** - critical acmeIdentifier extension, iPAddress SANs, reverse-arpa SNI names - ready for any TLS server (pairs naturally with [lemon-tls](https://github.com/colocohen/lemon-tls))
- Event-driven API - no callback hell, no manual orchestration
- External signers for the account and certificate keys - HSM, KMS, remote or threshold signing - with timeouts, retries and clear errors
- Let's Encrypt and ZeroSSL support (any ACME-compatible CA)
- External Account Binding (EAB) for ZeroSSL
- Wildcard certificates (`*.example.com`)
- Certificate + CA chain separation
- CAA record preflight check (auto-skipped for IP identifiers)
- Challenge self-verification with fallback DNS resolvers (8.8.8.8, 1.1.1.1), skippable for NAT setups
- Automatic key generation (ECDSA P-256/P-384 or RSA), or bring your own key or signer
- Custom CSR fields (country, organization, etc.)
- badNonce auto-retry
- Certificate manager with persistent storage (CSV + JSON), lifetime-aware renewal for short-lived certificates
- ESM + CommonJS + TypeScript support


## 📁 Project Structure

```
cert-manager/
├── index.js                 - Public API (ESM)
├── index.cjs                - CommonJS wrapper
├── index.d.ts               - TypeScript definitions
├── package.json
├── src/
│   ├── order.js              - Certificate order engine (state machine)
│   ├── manager.js            - Certificate manager with auto-renewal + ARI
│   ├── crypto.js             - Keys, CSR, JWS, EAB, tls-alpn certs, ARI certIds
│   ├── signer.js             - PEM keys and external signers behind one interface
│   ├── certs.js              - certificates read by cryptographic-formats; issuer and signature checks (as lemon-tls's)
│   ├── http.js               - ACME HTTP client with JWS authentication
│   ├── verify.js             - DNS TXT / HTTP challenge verification + CAA check
│   ├── est.js                - EST client (RFC 7030): what createOrder runs for provider: { est }
│   └── providers.js          - the provider option: named CAs, { acme: url }, { est: url }
└── test/
    ├── signer.test.js        - signers, CSR, JWS, ALPN cert, ARI - checked with openssl
    ├── http.test.js          - badNonce and refused signatures, against a stand-in CA
    ├── pebble.test.js        - complete orders against Pebble
    └── est.test.js           - EST against a real EST server (ca-manager), checked with openssl
```

The formats - CSR, X.509, JWS, JWK - are written by [cryptographic-formats](https://github.com/colocohen/cryptographic-formats), which performs no cryptography: it hands back the exact bytes to sign, and cert-manager (or your signer) signs them.


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

Note: IP certificates and the `shortlived` profile are Let's Encrypt features; other CAs may differ.

### Any ACME server

```js
ssl.createOrder({
  domain: 'app.internal.example.com',
  email: 'admin@example.com',
  provider: { acme: 'https://ca.internal.example.com/acme/directory' },   // step-ca, ca-manager, Pebble...
  // caa: 'ca.internal.example.com' - its CAA identity, to run the CAA preflight; without it, skipped
});
```

The manager takes the same `provider`, and finds that server's ARI in its directory.

### EST

`provider: { est: url, label, ca }` - see [EST](#-est---private-cas-rfc-7030).

An unknown provider name is an error (`Invalid options: unknown provider`), never a silent fallback.


## 🧪 Testing

```bash
npm test
```

`test/certs.test.js` checks the issuer and signature checks one by one (a CA with the issuer's key under another name, two CAs of one name, a tampered signature, a certificate that only names itself), and `test/store.test.js` checks `mgr.store()` with certificates openssl makes: names, wildcards, IP addresses, a common name alone, another key, an expired certificate, a broken bundle, an older certificate. The unit tests check every CSR and certificate with `openssl`, and JWS signatures with `node:crypto`. The end-to-end tests run complete orders against [Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's ACME test server - all three challenge types, IP identifiers, wildcards, EAB, the manager, and signers that are slow, refuse, time out, return DER, or sign with the wrong key. They run when Pebble is installed:

```bash
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest

PEBBLE=$(go env GOPATH)/bin/pebble \
PEBBLE_CHALLTESTSRV=$(go env GOPATH)/bin/pebble-challtestsrv \
PEBBLE_DIR=$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@v2.10.1 \
npm test
```

EST is tested against a real EST server over HTTPS - [ca-manager](https://github.com/colocohen/ca-manager)'s, taken from the sibling directory or `CA_MANAGER=/path`: a password, a device certificate, a CA label, renewal with the current certificate and its fallback when revoked, 202 approvals and `pendingTimeout`, the chain after the CA rotated its root (verified by openssl with the old root only), and a dishonest server - a certificate for another key, from a CA it did not name, or a server certificate nobody trusts - refused. ca-manager is written by the same hands, so it is not an independent check of EST; [libest](https://github.com/cisco/libest) would be.

Pebble uses ports 14000, 14010, 15000, 15010; the tests serve challenges on 5001 and 5002, and DNS on 8053.


## 🛣 Roadmap

### ✅ Done
- ACME RFC 8555 - full protocol implementation
- dns-01, http-01, and tls-alpn-01 challenges
- IP address certificates (RFC 8738) - IPv4 + IPv6
- ACME certificate profiles (`shortlived` etc.)
- ARI (RFC 9773) - suggested windows + `replaces`
- tls-alpn-01 challenge certificate generation (RFC 8737)
- Event-driven API with automatic flow management
- Let's Encrypt + ZeroSSL support
- EAB (External Account Binding)
- Wildcard certificates
- Certificate + CA chain separation
- CAA record preflight check
- CSR with custom fields
- Certificate manager with auto-renewal (lifetime-aware)
- Persistent storage (CSV + JSON)
- External signers (HSM, KMS, remote signing) for account and certificate keys
- Any ACME server (`provider: { acme: url }`)
- EST (RFC 7030) - enroll, renew with the current certificate, approvals that take time; the manager over EST
- ESM + CommonJS + TypeScript support

### ⏳ Planned
- Certificate revocation (RFC 8555 §7.6)
- DNS provider API integration (Cloudflare, Route53)
- Account key rollover
- Per-identifier challenge types in mixed orders

_Community contributions are welcome! Please ⭐ star the repo to follow progress._


## 🙏 Sponsors

cert-manager is an evenings-and-weekends project, part of the [colocohen](https://github.com/colocohen) Node.js infrastructure stack (TLS, QUIC, DNSSEC, port mapping, and more).
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
