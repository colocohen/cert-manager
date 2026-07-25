
import * as crypto from 'node:crypto';
import { domainToASCII } from 'node:url';
import {
  SEQUENCE, SET, INTEGER, BIT_STRING, OCTET_STRING, OID, UTF8STRING, IA5STRING,
  PRINTABLESTRING, ASN1_NULL, EXPLICIT,
  encode_tag,
  OID_COMMON_NAME, OID_COUNTRY, OID_STATE, OID_LOCALITY, OID_ORGANIZATION, OID_ORG_UNIT,
  OID_EMAIL, OID_SAN, OID_EXTENSION_REQUEST,
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
 * Build a SAN (Subject Alternative Name) extension DER for CSR.
 * names: array of domain strings
 */
function buildSanExtension(names) {
  let parts = [];
  for (let i = 0; i < names.length; i++) {
    // dNSName is context tag [2], implicit — must be ASCII (punycode for IDN)
    let encoded = new TextEncoder().encode(toAsciiDomain(names[i]));
    parts.push(encode_tag(0x82, encoded));
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
  let commonName = toAsciiDomain(options.commonName || options.domain);
  let altNames = (options.altNames || []).map(toAsciiDomain);
  let emailAddress = options.emailAddress || null;

  // Ensure commonName is in altNames
  if (altNames.indexOf(commonName) < 0) {
    altNames = [commonName].concat(altNames);
  }

  let key_obj = crypto.createPrivateKey(private_key_pem);
  let key_type = key_obj.asymmetricKeyType; // 'ec' or 'rsa'
  let pub_obj = crypto.createPublicKey(key_obj);
  let pub_der = pub_obj.export({ type: 'spki', format: 'der' });

  // Build subject
  let subject_parts = [];

  // CN
  subject_parts.push(SET([
    SEQUENCE([
      OID(OID_COMMON_NAME),
      UTF8STRING(commonName),
    ])
  ]));

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
};
