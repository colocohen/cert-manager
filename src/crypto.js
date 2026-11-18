
import { sha256_sync } from 'cryptographic-primitives/sha2.js';
import { hmac_sync } from 'cryptographic-primitives/hmac.js';
import { random_bytes_sync } from 'cryptographic-primitives/random.js';
import { p256, p384 } from 'cryptographic-primitives/nist.js';
import * as RSA from 'cryptographic-primitives/rsa.js';
import * as PKCS8 from 'cryptographic-formats/pkcs8';
import * as keys from './keys.js';
import * as net from 'node:net';
import { domainToASCII } from 'node:url';
import { jws, x509, x509_build, csr_build, pem } from 'cryptographic-formats';
import { isSigner, loadKey, jwkThumbprint, publicJwk } from './signer.js';
import { readCert } from './certs.js';


// The bytes of every structure below - CSR, certificate, JWS - are written
// by cryptographic-formats (the formats) and signed here or by the caller's signer
// (the cryptography). cryptographic-formats hands back exactly the bytes to sign,
// so what is signed is never a re-encoding of what is sent.


/**
 * Generate a private key.
 * type: 'ecdsa' | 'rsa'
 * options: { curve: 'P-256' | 'P-384' } or { size: 2048 | 4096 }
 * Returns PEM string.
 */
function generateKey(type, options) {
  options = options || {};

  if (type === 'rsa') {
    let size = options.size || 2048;
    if (size < 2048) {
      throw new Error('RSA key size must be at least 2048 bits (got ' + size + ')');
    }
    let k = RSA.keygen_sync(size);
    let b = function (n) { return bigBytes(n); };
    return pem.encode(PKCS8.to_der({ algorithm: 'rsaEncryption', rsa: {
      n: b(k.n), e: b(k.e), d: b(k.d), p: b(k.p), q: b(k.q), dp: b(k.dp), dq: b(k.dq), qinv: b(k.qinv) } }), 'PRIVATE KEY');
  }

  if (type !== 'ecdsa') {
    throw new Error('Unsupported key type: ' + type + ' (supported: ecdsa, rsa)');
  }

  // ecdsa — the NIST name, the library's curve and cryptographic-formats' name
  let curve = options.curve || 'P-256';
  let curve_map = { 'P-256': [p256, 'secp256r1'], 'P-384': [p384, 'secp384r1'] };
  let c = curve_map[curve];
  if (!c) {
    throw new Error('Unsupported curve: ' + curve + ' (supported: P-256, P-384)');
  }

  let kp = c[0].keygen_sync();
  let der = PKCS8.to_der({ algorithm: 'ecPublicKey', curve: c[1], scalar: kp.sk, point: c[0].get_public_key_sync(kp.sk, false) });
  kp.sk.fill(0);
  return pem.encode(der, 'PRIVATE KEY');
}

// A non-negative bigint as big-endian bytes.
function bigBytes(n) {
  let h = n.toString(16);
  let buf = Buffer.from(h.length % 2 ? '0' + h : h, 'hex');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}


/**
 * The public JWK of an account key - a PEM private key, or a signer (its
 * publicKey). Only the public members, in RFC 7638's set.
 */
function getJwk(key) {
  if (isSigner(key)) return loadKey(key, { use: 'account' }).jwk;
  return publicJwk(keys.privateKey(key));
}


/**
 * JWK thumbprint (RFC 7638) — used for challenge key authorizations.
 */
function getJwkThumbprint(jwk) {
  if (!jwk || (jwk.kty !== 'EC' && jwk.kty !== 'RSA')) {
    throw new Error('Unsupported JWK key type: ' + (jwk && jwk.kty) + ' (supported: EC, RSA)');
  }
  return jwkThumbprint(jwk);
}


/**
 * Convert a domain to ASCII (punycode) for use in identifiers, SANs and CN.
 * Handles a leading wildcard label ("*.") which domainToASCII rejects.
 * Returns the input unchanged if conversion fails (already ASCII / invalid).
 */
function toAsciiDomain(name) {
  if (typeof name !== 'string') return name;
  // IP addresses are never punycoded — domainToASCII would mangle or reject
  // them (IPv6 contains ':'). They pass through untouched.
  if (net.isIP(name)) return name;
  let wildcard = false;
  let n = name;
  if (n.indexOf('*.') === 0) {
    wildcard = true;
    n = n.substring(2);
  }
  let ascii = domainToASCII(n);
  if (!ascii) ascii = n;
  return (wildcard ? '*.' : '') + ascii;
}


/**
 * Convert an IP address string to its raw byte representation.
 * IPv4 → 4 bytes, IPv6 → 16 bytes (RFC 5280 requires raw octets for
 * iPAddress SAN entries — never the textual form).
 * Throws on anything that is not a valid IP.
 */
function ipToBytes(ip) {
  if (net.isIPv4(ip)) {
    let p = ip.split('.');
    return new Uint8Array([p[0] & 0xFF, p[1] & 0xFF, p[2] & 0xFF, p[3] & 0xFF]);
  }

  if (!net.isIPv6(ip)) {
    throw new Error('Not a valid IP address: ' + ip);
  }

  let n = ip;

  // Strip zone index (fe80::1%eth0) — not part of the address bytes
  let zone = n.indexOf('%');
  if (zone >= 0) n = n.substring(0, zone);

  // IPv4-embedded tail (::ffff:1.2.3.4) → convert to two hex groups
  if (n.indexOf('.') >= 0) {
    let last = n.lastIndexOf(':');
    let v4 = n.substring(last + 1).split('.');
    let hi = (((v4[0] & 0xFF) << 8) | (v4[1] & 0xFF)).toString(16);
    let lo = (((v4[2] & 0xFF) << 8) | (v4[3] & 0xFF)).toString(16);
    n = n.substring(0, last + 1) + hi + ':' + lo;
  }

  // Expand '::' — split into left/right group lists, pad zeros in between
  let halves = n.split('::');
  let left = halves[0] ? halves[0].split(':') : [];
  let right = (halves.length > 1 && halves[1]) ? halves[1].split(':') : [];
  let groups = left.slice();
  let missing = 8 - left.length - right.length;
  for (let i = 0; i < missing; i++) groups.push('0');
  for (let i = 0; i < right.length; i++) groups.push(right[i]);

  let bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    let val = parseInt(groups[i] || '0', 16);
    bytes[i * 2] = (val >> 8) & 0xFF;
    bytes[i * 2 + 1] = val & 0xFF;
  }
  return bytes;
}


/**
 * Canonical textual form of an IP address.
 * IPv4 is returned as-is (net.isIPv4 already rejects ambiguous forms).
 * IPv6 is normalized per RFC 5952 §4 — the form RFC 8738 requires for ACME
 * identifiers: lowercase hex, no leading zeros, '::' compressing the longest
 * run of zero groups (leftmost on ties), never compressing a single group.
 * '2A02:C202:0:0:0:0:0:1' → '2a02:c202::1'. Zone indexes are stripped.
 */
function canonicalIp(ip) {
  if (net.isIPv4(ip)) return ip;

  let bytes = ipToBytes(ip);   // throws if not a valid IP

  let groups = [];
  for (let i = 0; i < 8; i++) {
    groups.push(((bytes[i * 2] << 8) | bytes[i * 2 + 1]).toString(16));
  }

  // Longest run of zero groups (length >= 2), leftmost wins ties
  let best_start = -1, best_len = 0;
  let run_start = -1, run_len = 0;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === '0') {
      if (run_start < 0) { run_start = i; run_len = 0; }
      run_len++;
    } else {
      if (run_len > best_len) { best_start = run_start; best_len = run_len; }
      run_start = -1; run_len = 0;
    }
  }

  if (best_len < 2) return groups.join(':');

  let left = groups.slice(0, best_start).join(':');
  let right = groups.slice(best_start + best_len).join(':');
  return left + '::' + right;
}


/**
 * Reverse-mapped DNS name for an IP address (RFC 1034 / RFC 3596).
 * Needed for tls-alpn-01 with IP identifiers: RFC 8738 forbids putting the
 * IP itself in SNI, so the validation server sends the in-addr.arpa /
 * ip6.arpa name instead. 81.2.3.4 → '4.3.2.81.in-addr.arpa'
 */
function ipToArpa(ip) {
  let bytes = ipToBytes(ip);

  if (bytes.length === 4) {
    return bytes[3] + '.' + bytes[2] + '.' + bytes[1] + '.' + bytes[0] + '.in-addr.arpa';
  }

  // IPv6 — 32 nibbles, least significant first
  let nibbles = [];
  for (let i = bytes.length - 1; i >= 0; i--) {
    nibbles.push((bytes[i] & 0x0F).toString(16));
    nibbles.push(((bytes[i] >> 4) & 0x0F).toString(16));
  }
  return nibbles.join('.') + '.ip6.arpa';
}


/**
 * A SAN entry as cryptographic-formats takes it. IPs go as raw bytes (4 or 16,
 * RFC 5280) - ipToBytes has already dropped any zone index, which has no
 * place in a certificate. Domains go as ASCII (punycode for IDN).
 */
function sanEntry(name) {
  if (net.isIP(name)) return { ip: ipToBytes(name) };
  return { dns: toAsciiDomain(name) };
}


/**
 * The CSR's parts: the subject and SANs from the options, the key's public
 * half and algorithm. Shared by the sync (PEM) and async (signer) paths.
 */
function csrRequest(options, key) {
  let primary = options.commonName || options.domain || null;
  let altNames = (options.altNames || []).map(toAsciiDomain);
  let emailAddress = options.emailAddress || null;

  // Ensure the primary name is in altNames (toAsciiDomain is a no-op for IPs)
  if (primary) {
    primary = toAsciiDomain(primary);
    if (altNames.indexOf(primary) < 0) {
      altNames = [primary].concat(altNames);
    }
  }

  if (altNames.length === 0) {
    throw new Error('createCsr requires at least one name (commonName/domain/altNames)');
  }

  let subject = [];

  // CN — only for domain names, and only when we have one.
  // IP addresses never go into the CN: CAs omit the CN for IP certificates
  // (Let's Encrypt's tlsserver/shortlived profiles contain no CN at all),
  // and an IP belongs in the SAN as iPAddress bytes, not as Subject text.
  // PKCS#10 permits an empty subject when a SAN extension is present.
  if (primary && !net.isIP(primary)) subject.push({ commonName: primary });

  // Country (C) — X.520 mandates PrintableString of exactly 2 characters
  if (options.country) {
    let country = String(options.country).toUpperCase();
    if (!/^[A-Z]{2}$/.test(country)) {
      throw new Error('country must be a 2-letter ISO 3166 code (got "' + options.country + '")');
    }
    subject.push({ countryName: country });
  }
  if (options.state) subject.push({ stateOrProvinceName: options.state });
  if (options.locality) subject.push({ localityName: options.locality });
  if (options.organization) subject.push({ organizationName: options.organization });
  if (options.organizationUnit) subject.push({ organizationalUnitName: options.organizationUnit });
  if (emailAddress) subject.push({ emailAddress: emailAddress });

  return csr_build.prepare({
    subject: subject,
    public_key: key.spki,
    signature_algorithm: key.alg.x509,
    extensions: { subjectAltName: altNames.map(sanEntry) },
  });
}


/**
 * Create a CSR (Certificate Signing Request).
 *
 *   createCsr(options, privateKeyPem)                  → DER Uint8Array (as before)
 *   createCsr(options, privateKeyPemOrSigner, callback) → callback(err, der)
 *
 * options: { commonName, altNames: [], emailAddress, country, state,
 *            locality, organization, organizationUnit }
 * The callback form also takes a signer { publicKey, sign, ... } - the
 * certificate's key held in an HSM or KMS (see signer.js).
 */
function createCsr(options, private_key, callback) {
  if (typeof callback === 'function') {
    let key, prepared;
    try {
      key = loadKey(private_key, { use: 'certificate', signTimeout: options.signTimeout, signRetries: options.signRetries });
      prepared = csrRequest(options, key);
    } catch (e) {
      return setImmediate(callback, e);
    }
    key.sign(prepared.bytes, 'der', function(err, sig) {
      if (err) return callback(err);
      let der;
      try { der = csr_build.assemble(prepared, sig); } catch (e) { return callback(e); }
      callback(null, der);
    });
    return;
  }

  if (isSigner(private_key)) {
    throw new Error('createCsr: a signer signs asynchronously - pass a callback: createCsr(options, signer, function(err, der) {})');
  }

  let key = loadKey(private_key, { use: 'certificate' });
  let prepared = csrRequest(options, key);
  let sig = keys.privateKey(private_key).sign(key.alg.hash, prepared.bytes, 'der');   // DER for ECDSA, as X.509 wants
  return csr_build.assemble(prepared, sig);
}


/**
 * Build the self-signed validation certificate for tls-alpn-01 (RFC 8737),
 * including the RFC 8738 rules for IP identifiers.
 *
 * identifier: domain string or IP string (the ACME identifier value)
 * key_authorization: '<token>.<jwk-thumbprint>' string
 *
 * Returns { cert, key } — both PEM, ready for a TLS server
 * (e.g. lemon-tls createSecureContext({ cert, key })).
 *
 * The certificate contains, per RFC 8737 §3:
 *  - subjectAltName with EXACTLY ONE entry: dNSName for domains,
 *    iPAddress (raw bytes) for IPs (RFC 8738 §6)
 *  - a CRITICAL acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31) whose
 *    extnValue is the DER of `Authorization ::= OCTET STRING (SIZE (32))`
 *    holding the SHA-256 digest of the key authorization. Since extnValue
 *    is itself an OCTET STRING (RFC 5280), the wire bytes are a DOUBLE
 *    OCTET STRING: 04 22 04 20 <32 digest bytes>. One layer only = the
 *    classic implementation bug, and the CA rejects it without explanation.
 *    cryptographic-formats writes the outer layer; the inner one (04 20 ...) is here.
 */
function createAlpnCertificate(identifier, key_authorization) {
  // Fresh key just for the challenge cert — never reuse the account or
  // certificate keys for a throwaway self-signed artifact
  let key_pem = generateKey('ecdsa', { curve: 'P-256' });
  let key = keys.privateKey(key_pem);

  let digest = sha256_sync(key_authorization);
  let authorization = new Uint8Array(2 + digest.length);
  authorization[0] = 0x04;                 // OCTET STRING
  authorization[1] = digest.length;        // 32
  authorization.set(digest, 2);

  // A short fixed CN for subject/issuer. RFC 8737 doesn't require an empty
  // subject, and RFC 5280 would force SAN to be critical if it were empty —
  // a non-empty name keeps strict parsers happy. (The identifier itself
  // can't be the CN: an ip6.arpa name exceeds the 64-char CN limit.)
  let name = [{ commonName: 'ACME TLS-ALPN Challenge' }];

  let now = Date.now();
  let tbs = x509_build.prepare({
    serial: random_bytes_sync(12),
    issuer: name,
    subject: name,
    validity: {
      not_before: new Date(now - 5 * 60000),        // 5 min back — clock skew
      not_after: new Date(now + 24 * 3600000),      // challenges live minutes, 24h is plenty
    },
    public_key: key.spki,
    signature_algorithm: 'ecdsaWithSHA256',
    extensions: {
      // SAN — exactly one entry (RFC 8737: "and no other entries")
      subjectAltName: [sanEntry(identifier)],
      // acmeIdentifier — MUST be critical
      '1.3.6.1.5.5.7.1.31': { value: authorization, critical: true },
    },
  });

  let signature = key.sign('sha256', tbs.bytes, 'der');
  let cert_der = x509_build.assemble(tbs, signature);

  return {
    cert: pemEncode(cert_der, 'CERTIFICATE'),
    key: key_pem,
  };
}


/**
 * The JWS parts for an ACME request: payload '' for POST-as-GET, anything
 * else as JSON. A header without `alg` gets the key's.
 */
function jwsRequest(payload, protected_header, key) {
  let header = protected_header;
  if (header.alg === undefined) {
    header = Object.assign({ alg: key.alg.jws }, protected_header);
  }
  let body = (payload === '') ? '' : JSON.stringify(payload);
  return jws.prepare(header, body);
}


/**
 * Sign data with JWS (JSON Web Signature) for ACME requests.
 *
 *   signJws(payload, header, privateKeyPem)                  → { protected, payload, signature }
 *   signJws(payload, header, privateKeyPemOrSigner, callback) → callback(err, jws)
 *
 * payload: object or empty string (for POST-as-GET)
 * The callback form also takes a signer (see signer.js). ECDSA signatures
 * are the raw r||s pair JOSE requires - converted from DER if the signer
 * returns that.
 */
function signJws(payload, protected_header, private_key, callback) {
  if (typeof callback === 'function') {
    let key, prepared;
    try {
      key = loadKey(private_key, { use: 'account' });
      prepared = jwsRequest(payload, protected_header, key);
    } catch (e) {
      return setImmediate(callback, e);
    }
    key.sign(prepared.bytes, 'raw', function(err, sig) {
      if (err) return callback(err);
      let out;
      try { out = jws.assemble(prepared, sig, { serialization: 'flattened' }); } catch (e) { return callback(e); }
      callback(null, out);
    });
    return;
  }

  if (isSigner(private_key)) {
    throw new Error('signJws: a signer signs asynchronously - pass a callback: signJws(payload, header, signer, function(err, jws) {})');
  }

  let key = loadKey(private_key, { use: 'account' });
  let prepared = jwsRequest(payload, protected_header, key);
  let sig = keys.privateKey(private_key).sign(key.alg.hash, prepared.bytes, 'raw');
  return jws.assemble(prepared, sig, { serialization: 'flattened' });
}


/**
 * Base64url encode.
 */
function base64url(data) {
  let buf = null;
  if (data instanceof Uint8Array) {
    buf = Buffer.from(data);
  } else if (Buffer.isBuffer(data)) {
    buf = data;
  } else if (typeof data === 'string') {
    buf = Buffer.from(data);
  } else {
    buf = Buffer.from(data);
  }
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}


/**
 * Sign External Account Binding (EAB) for ZeroSSL and other CAs.
 * eab_kid: string (from CA)
 * eab_hmac_key: string (base64, from CA)
 * account_jwk: object (public JWK of account key)
 * url: string (newAccount URL)
 * Returns { protected, payload, signature } JWS object.
 *
 * An HMAC with the CA's key, not a signature - the account key is never
 * involved, so this stays synchronous even when the account key is a signer.
 */
function signEab(eab_kid, eab_hmac_key, account_jwk, url) {
  let prepared = jws.prepare({ alg: 'HS256', kid: eab_kid, url: url }, JSON.stringify(account_jwk));
  // RFC 8555 §7.3.4 says base64url; some CAs hand out standard base64.
  // Node's 'base64' decoder reads both alphabets.
  let hmac_key = Buffer.from(eab_hmac_key, 'base64');
  let mac = hmac_sync(sha256_sync, hmac_key, prepared.bytes);
  return jws.assemble(prepared, mac, { serialization: 'flattened' });
}


/**
 * The first certificate's DER, from PEM (a chain is fine) or DER bytes.
 */
function firstCertificateDer(cert_pem_or_der) {
  if (typeof cert_pem_or_der !== 'string') return new Uint8Array(cert_pem_or_der);
  let blocks = pem.decode(cert_pem_or_der);
  for (let i = 0; i < blocks.length; i++) {
    if (blocks[i].label === 'CERTIFICATE') return blocks[i].der;
  }
  throw new Error('no CERTIFICATE block');
}


/**
 * ARI certificate identifier (RFC 9773 §4.1):
 *   base64url(AKI keyIdentifier bytes) + '.' + base64url(serial DER content bytes)
 * The serial bytes are taken VERBATIM from the certificate's DER — including
 * a leading 0x00 sign byte if present (the spec's own example, 00:87:65:43:21,
 * keeps it). Trailing '=' padding is stripped (base64url() already does).
 *
 * Accepts PEM string or DER bytes. Returns the id string, or null if the
 * certificate has no AKI extension (e.g. some self-signed certs) — in which
 * case ARI simply isn't applicable.
 */
function getAriCertId(cert_pem_or_der) {
  try {
    let cert = x509.from_der(firstCertificateDer(cert_pem_or_der));
    let aki = x509.extension(cert, 'authorityKeyId');
    let key_id = aki && aki.parsed ? aki.parsed.key_id : null;
    if (!key_id || key_id.length === 0 || !cert.serial || cert.serial.length === 0) return null;
    return base64url(key_id) + '.' + base64url(cert.serial);
  } catch (e) {
    return null;
  }
}


/**
 * Extract validity dates from a certificate PEM (its first certificate,
 * read by cryptographic-formats).
 * Returns { issued: Date, expires: Date } or null on parse failure.
 * (Single source of truth — used by both the order engine and the manager.)
 */
function getCertDates(cert_pem) {
  try {
    let cert = readCert(cert_pem);
    return { issued: new Date(cert.notBefore.getTime()), expires: new Date(cert.notAfter.getTime()) };
  } catch (e) { return null; }
}


/**
 * Encode DER bytes as PEM with the given label (cryptographic-formats, RFC 7468).
 * pemEncode(der, 'CERTIFICATE REQUEST') → '-----BEGIN CERTIFICATE REQUEST-----\n...'
 * Strings are returned unchanged (assumed to already be PEM).
 */
function pemEncode(der, label) {
  if (typeof der === 'string') return der;
  return pem.encode(der, label);
}


/**
 * A CSR as DER, from what a caller may hand in: DER bytes, or PEM text.
 * (A PEM string used to be base64url'd as text and sent to the CA as is -
 * which no CA accepts.)
 */
function csrToDer(csr) {
  if (typeof csr !== 'string') return new Uint8Array(csr);
  return pem.decode_one(csr, 'CERTIFICATE REQUEST').der;
}


export {
  generateKey,
  getJwk,
  getJwkThumbprint,
  createCsr,
  signJws,
  signEab,
  base64url,
  pemEncode,
  toAsciiDomain,
  ipToBytes,
  ipToArpa,
  canonicalIp,
  createAlpnCertificate,
  getAriCertId,
  getCertDates,
  csrToDer,
};
