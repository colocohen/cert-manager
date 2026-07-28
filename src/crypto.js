
import * as crypto from 'node:crypto';
import * as net from 'node:net';
import { domainToASCII } from 'node:url';
import {
  SEQUENCE, SET, INTEGER, BIT_STRING, OCTET_STRING, OID, UTF8STRING, IA5STRING,
  PRINTABLESTRING, ASN1_NULL, BOOLEAN, UTCTIME, EXPLICIT, read_tlv,
  encode_tag,
  OID_COMMON_NAME, OID_COUNTRY, OID_STATE, OID_LOCALITY, OID_ORGANIZATION, OID_ORG_UNIT,
  OID_EMAIL, OID_SAN, OID_EXTENSION_REQUEST, OID_ACME_IDENTIFIER,
  OID_ECDSA_SHA256, OID_ECDSA_SHA384, OID_SHA256_RSA,
  OID_EC_PUBLIC_KEY, OID_RSA_PUBLIC_KEY, OID_P256, OID_P384,
} from './asn1.js';


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
    let pair = crypto.generateKeyPairSync('rsa', {
      modulusLength: size,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return pair.privateKey;
  }

  if (type !== 'ecdsa') {
    throw new Error('Unsupported key type: ' + type + ' (supported: ecdsa, rsa)');
  }

  // ecdsa — map NIST names to OpenSSL curve names (works on all Node versions)
  let curve = options.curve || 'P-256';
  let curve_map = { 'P-256': 'prime256v1', 'P-384': 'secp384r1' };
  let namedCurve = curve_map[curve];
  if (!namedCurve) {
    throw new Error('Unsupported curve: ' + curve + ' (supported: P-256, P-384)');
  }

  let pair = crypto.generateKeyPairSync('ec', {
    namedCurve: namedCurve,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return pair.privateKey;
}


/**
 * Get JWK thumbprint from a PEM private key (for ACME account key).
 * Returns the JWK public key object.
 */
function getJwk(pem_private_key) {
  let key_obj = crypto.createPrivateKey(pem_private_key);
  let jwk = key_obj.export({ format: 'jwk' });

  // Return only public components
  if (jwk.kty === 'EC') {
    return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
  }
  if (jwk.kty === 'RSA') {
    return { kty: 'RSA', n: jwk.n, e: jwk.e };
  }

  return jwk;
}


/**
 * JWK thumbprint (RFC 7638) — used for challenge key authorizations.
 */
function getJwkThumbprint(jwk) {
  let ordered = null;

  if (jwk.kty === 'EC') {
    ordered = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  } else if (jwk.kty === 'RSA') {
    ordered = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
  } else {
    throw new Error('Unsupported JWK key type: ' + jwk.kty + ' (supported: EC, RSA)');
  }

  let hash = crypto.createHash('sha256').update(ordered).digest();
  return base64url(hash);
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
 * Build a SAN (Subject Alternative Name) extension DER for CSR.
 * names: array of domain strings and/or IP address strings.
 * Domains → dNSName (context tag [2], ASCII/punycode).
 * IPs     → iPAddress (context tag [7], raw 4/16 bytes per RFC 5280).
 */
function buildSanExtension(names) {
  let parts = [];
  for (let i = 0; i < names.length; i++) {
    if (net.isIP(names[i])) {
      parts.push(encode_tag(0x87, ipToBytes(names[i])));
    } else {
      // dNSName is context tag [2], implicit — must be ASCII (punycode for IDN)
      let encoded = new TextEncoder().encode(toAsciiDomain(names[i]));
      parts.push(encode_tag(0x82, encoded));
    }
  }
  let total = 0;
  for (let i = 0; i < parts.length; i++) total += parts[i].length;
  let content = new Uint8Array(total);
  let off = 0;
  for (let i = 0; i < parts.length; i++) {
    content.set(parts[i], off);
    off += parts[i].length;
  }
  return SEQUENCE([ content ]);
}


/**
 * Create a CSR (Certificate Signing Request).
 * options: { commonName, altNames: [], emailAddress }
 * private_key_pem: PEM private key string
 * Returns DER Uint8Array.
 */
function createCsr(options, private_key_pem) {
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

  let key_obj = crypto.createPrivateKey(private_key_pem);
  let key_type = key_obj.asymmetricKeyType; // 'ec' or 'rsa'
  let pub_obj = crypto.createPublicKey(key_obj);
  let pub_der = pub_obj.export({ type: 'spki', format: 'der' });

  // Build subject
  let subject_parts = [];

  // CN — only for domain names, and only when we have one.
  // IP addresses never go into the CN: CAs omit the CN for IP certificates
  // (Let's Encrypt's tlsserver/shortlived profiles contain no CN at all),
  // and an IP belongs in the SAN as iPAddress bytes, not as Subject text.
  // PKCS#10 permits an empty subject when a SAN extension is present.
  if (primary && !net.isIP(primary)) {
    subject_parts.push(SET([
      SEQUENCE([
        OID(OID_COMMON_NAME),
        UTF8STRING(primary),
      ])
    ]));
  }

  // Country (C) — X.520 mandates PrintableString of exactly 2 characters
  if (options.country) {
    let country = String(options.country).toUpperCase();
    if (!/^[A-Z]{2}$/.test(country)) {
      throw new Error('country must be a 2-letter ISO 3166 code (got "' + options.country + '")');
    }
    subject_parts.push(SET([ SEQUENCE([ OID(OID_COUNTRY), PRINTABLESTRING(country) ]) ]));
  }

  // State (ST)
  if (options.state) {
    subject_parts.push(SET([ SEQUENCE([ OID(OID_STATE), UTF8STRING(options.state) ]) ]));
  }

  // Locality (L)
  if (options.locality) {
    subject_parts.push(SET([ SEQUENCE([ OID(OID_LOCALITY), UTF8STRING(options.locality) ]) ]));
  }

  // Organization (O)
  if (options.organization) {
    subject_parts.push(SET([ SEQUENCE([ OID(OID_ORGANIZATION), UTF8STRING(options.organization) ]) ]));
  }

  // Organizational Unit (OU)
  if (options.organizationUnit) {
    subject_parts.push(SET([ SEQUENCE([ OID(OID_ORG_UNIT), UTF8STRING(options.organizationUnit) ]) ]));
  }

  // emailAddress
  if (emailAddress) {
    subject_parts.push(SET([
      SEQUENCE([
        OID(OID_EMAIL),
        IA5STRING(emailAddress),
      ])
    ]));
  }

  let subject = SEQUENCE(subject_parts);

  // Build SAN extension
  let san_ext = buildSanExtension(altNames);

  // Extension request attribute (PKCS#10 extensionRequest)
  let ext_request = EXPLICIT(0,
    SEQUENCE([
      OID(OID_EXTENSION_REQUEST),
      SET([
        SEQUENCE([
          SEQUENCE([
            OID(OID_SAN),
            OCTET_STRING(san_ext),
          ])
        ])
      ])
    ])
  );

  // CertificationRequestInfo
  let cri = SEQUENCE([
    INTEGER(0), // version
    subject,
    new Uint8Array(pub_der), // SubjectPublicKeyInfo
    ext_request,
  ]);

  // Sign
  let sig_alg_oid = null;
  let hash_alg = 'sha256';

  if (key_type === 'ec') {
    let jwk = key_obj.export({ format: 'jwk' });
    if (jwk.crv === 'P-384') {
      sig_alg_oid = OID_ECDSA_SHA384;
      hash_alg = 'sha384';
    } else {
      sig_alg_oid = OID_ECDSA_SHA256;
      hash_alg = 'sha256';
    }
  } else {
    sig_alg_oid = OID_SHA256_RSA;
    hash_alg = 'sha256';
  }

  let signer = crypto.createSign(hash_alg);
  signer.update(cri);
  let signature = signer.sign(key_obj);

  // AlgorithmIdentifier:
  //  - ECDSA (RFC 5754 §3.3): parameters field MUST be absent
  //  - RSA   (RFC 5754 §3.2): parameters field MUST be an explicit NULL
  let sig_alg = (key_type === 'ec')
    ? SEQUENCE([OID(sig_alg_oid)])
    : SEQUENCE([OID(sig_alg_oid), ASN1_NULL()]);

  // Build CSR
  let csr = SEQUENCE([
    cri,
    sig_alg,
    BIT_STRING(new Uint8Array(signature)),
  ]);

  return csr;
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
 */
function createAlpnCertificate(identifier, key_authorization) {
  // Fresh key just for the challenge cert — never reuse the account or
  // certificate keys for a throwaway self-signed artifact
  let key_pem = generateKey('ecdsa', { curve: 'P-256' });
  let key_obj = crypto.createPrivateKey(key_pem);
  let pub_der = crypto.createPublicKey(key_obj).export({ type: 'spki', format: 'der' });

  let digest = crypto.createHash('sha256').update(key_authorization).digest();

  // SAN — exactly one entry (RFC 8737: "and no other entries")
  let san_entry = net.isIP(identifier)
    ? encode_tag(0x87, ipToBytes(identifier))                          // iPAddress
    : encode_tag(0x82, new TextEncoder().encode(toAsciiDomain(identifier))); // dNSName
  let san_value = SEQUENCE([ san_entry ]);

  // A short fixed CN for subject/issuer. RFC 8737 doesn't require an empty
  // subject, and RFC 5280 would force SAN to be critical if it were empty —
  // a non-empty name keeps strict parsers happy. (The identifier itself
  // can't be the CN: an ip6.arpa name exceeds the 64-char CN limit.)
  let name = SEQUENCE([
    SET([ SEQUENCE([ OID(OID_COMMON_NAME), UTF8STRING('ACME TLS-ALPN Challenge') ]) ])
  ]);

  let now = Date.now();
  let validity = SEQUENCE([
    UTCTIME(new Date(now - 5 * 60000)),        // 5 min back — clock skew
    UTCTIME(new Date(now + 24 * 3600000)),     // challenges live minutes, 24h is plenty
  ]);

  // Extension ::= SEQUENCE { extnID, critical BOOLEAN, extnValue OCTET STRING }
  let extensions = EXPLICIT(3, SEQUENCE([
    // subjectAltName — non-critical (subject is non-empty)
    SEQUENCE([ OID(OID_SAN), OCTET_STRING(san_value) ]),
    // acmeIdentifier — MUST be critical; note the double OCTET STRING
    SEQUENCE([
      OID(OID_ACME_IDENTIFIER),
      BOOLEAN(true),
      OCTET_STRING( OCTET_STRING(new Uint8Array(digest)) ),
    ]),
  ]));

  let sig_alg = SEQUENCE([ OID(OID_ECDSA_SHA256) ]);  // EC: parameters absent (RFC 5754)

  let serial = new Uint8Array(crypto.randomBytes(12));

  let tbs = SEQUENCE([
    EXPLICIT(0, INTEGER(2)),      // version v3
    INTEGER(serial),
    sig_alg,
    name,                          // issuer (self-signed)
    validity,
    name,                          // subject
    new Uint8Array(pub_der),       // SubjectPublicKeyInfo
    extensions,
  ]);

  let signer = crypto.createSign('sha256');
  signer.update(tbs);
  let signature = signer.sign(key_obj);

  let cert_der = SEQUENCE([
    tbs,
    sig_alg,
    BIT_STRING(new Uint8Array(signature)),
  ]);

  return {
    cert: pemEncode(cert_der, 'CERTIFICATE'),
    key: key_pem,
  };
}


/**
 * Sign data with JWS (JSON Web Signature) for ACME requests.
 * payload: object or empty string (for POST-as-GET)
 * protected_header: object
 * private_key_pem: PEM private key string
 * Returns { protected, payload, signature } object ready for JSON.
 */
function signJws(payload, protected_header, private_key_pem) {
  let key_obj = crypto.createPrivateKey(private_key_pem);
  let key_type = key_obj.asymmetricKeyType;

  let protected_b64 = base64url(Buffer.from(JSON.stringify(protected_header)));

  let payload_b64 = '';
  if (payload === '') {
    payload_b64 = '';
  } else {
    payload_b64 = base64url(Buffer.from(JSON.stringify(payload)));
  }

  let signing_input = protected_b64 + '.' + payload_b64;

  // Hash must match the JWS "alg" header (see getAlgFromKey in http.js):
  // P-256 → ES256/sha256, P-384 → ES384/sha384, P-521 → ES512/sha512, RSA → RS256/sha256
  let alg = 'sha256';
  if (key_type === 'ec') {
    let jwk = key_obj.export({ format: 'jwk' });
    if (jwk.crv === 'P-384') alg = 'sha384';
    else if (jwk.crv === 'P-521') alg = 'sha512';
    else if (jwk.crv !== 'P-256') {
      throw new Error('Unsupported EC curve for JWS: ' + jwk.crv);
    }
  }

  let signer = crypto.createSign(alg);
  signer.update(signing_input);

  let sig = signer.sign({
    key: key_obj,
    dsaEncoding: 'ieee-p1363',
  });

  return {
    protected: protected_b64,
    payload: payload_b64,
    signature: base64url(sig),
  };
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
 */
function signEab(eab_kid, eab_hmac_key, account_jwk, url) {
  let protected_header = {
    alg: 'HS256',
    kid: eab_kid,
    url: url,
  };

  let protected_b64 = base64url(Buffer.from(JSON.stringify(protected_header)));
  let payload_b64 = base64url(Buffer.from(JSON.stringify(account_jwk)));

  let signing_input = protected_b64 + '.' + payload_b64;
  let hmac_key = Buffer.from(eab_hmac_key, 'base64');
  let sig = crypto.createHmac('sha256', hmac_key).update(signing_input).digest();

  return {
    protected: protected_b64,
    payload: payload_b64,
    signature: base64url(sig),
  };
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
  let der = null;
  if (typeof cert_pem_or_der === 'string') {
    let b64 = cert_pem_or_der.replace(/-----[A-Z ]+-----/g, '').replace(/[\r\n\s]/g, '');
    der = new Uint8Array(Buffer.from(b64, 'base64'));
  } else {
    der = new Uint8Array(cert_pem_or_der);
  }

  try {
    let cert = read_tlv(der, 0);           // Certificate ::= SEQUENCE
    let tbs = read_tlv(der, cert.start);   // tbsCertificate ::= SEQUENCE

    let off = tbs.start;
    let first = read_tlv(der, off);
    if (first.tag === 0xA0) off = first.next;   // [0] EXPLICIT version (v3)

    let serial_tlv = read_tlv(der, off);        // serialNumber INTEGER
    let serial = der.slice(serial_tlv.start, serial_tlv.end);

    // Walk the remaining TBS fields to the extensions container [3]
    let p = serial_tlv.next;
    let ext_container = null;
    while (p < tbs.end) {
      let t = read_tlv(der, p);
      if (t.tag === 0xA3) { ext_container = t; break; }
      p = t.next;
    }
    if (!ext_container) return null;

    let exts = read_tlv(der, ext_container.start);   // SEQUENCE OF Extension
    let q = exts.start;
    while (q < exts.end) {
      let ext = read_tlv(der, q);                    // Extension ::= SEQUENCE
      let oid = read_tlv(der, ext.start);
      // authorityKeyIdentifier = OID 2.5.29.35 = 55 1D 23
      let is_aki = (oid.tag === 0x06 && (oid.end - oid.start) === 3 &&
                    der[oid.start] === 0x55 && der[oid.start + 1] === 0x1D && der[oid.start + 2] === 0x23);
      if (is_aki) {
        let r = oid.next;
        let val = read_tlv(der, r);
        if (val.tag === 0x01) { val = read_tlv(der, val.next); }   // skip critical BOOLEAN if present
        // val = extnValue OCTET STRING → AuthorityKeyIdentifier ::= SEQUENCE
        let inner = read_tlv(der, val.start);
        let s = inner.start;
        while (s < inner.end) {
          let f = read_tlv(der, s);
          if (f.tag === 0x80) {                       // [0] IMPLICIT keyIdentifier
            let aki = der.slice(f.start, f.end);
            if (aki.length === 0 || serial.length === 0) return null;
            return base64url(aki) + '.' + base64url(serial);
          }
          s = f.next;
        }
        return null;
      }
      q = ext.next;
    }
    return null;
  } catch (e) {
    return null;
  }
}


/**
 * Extract validity dates from a certificate PEM.
 * Returns { issued: Date, expires: Date } or null on parse failure.
 * (Single source of truth — used by both the order engine and the manager.)
 */
function getCertDates(cert_pem) {
  try {
    let x509 = new crypto.X509Certificate(cert_pem);
    return { issued: new Date(x509.validFrom), expires: new Date(x509.validTo) };
  } catch (e) { return null; }
}


/**
 * Encode DER bytes as PEM with the given label.
 * pemEncode(der, 'CERTIFICATE REQUEST') → '-----BEGIN CERTIFICATE REQUEST-----\n...'
 * Strings are returned unchanged (assumed to already be PEM).
 */
function pemEncode(der, label) {
  if (typeof der === 'string') return der;
  let b64 = Buffer.from(der).toString('base64');
  let lines = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.substring(i, i + 64));
  }
  return '-----BEGIN ' + label + '-----\n' + lines.join('\n') + '\n-----END ' + label + '-----\n';
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
};
