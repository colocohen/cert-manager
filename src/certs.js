// Certificates as cert-manager handles them: read by cryptographic-formats, the
// issuer matched by name and key identifier, the signature checked by
// node:crypto.
//
// The issuer and signature checks are the ones lemon-tls's
// src/session/x509.js makes, copied (the chain they build is a verifier's
// decision, not a format, so it is not cryptographic-formats'): a change to one
// belongs in the other.

import * as keys from './keys.js';
import { x509, pem } from 'cryptographic-formats';

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * The PEM text of every CERTIFICATE block in `text`, each as cryptographic-formats
 * writes it; [] when there is none. Throws on a block that does not decode
 * (a chain is not guessed at): err.code is cryptographic-formats'.
 */
function certificatePems(text) {
  let blocks;
  try { blocks = pem.decode(String(text)); }
  catch (e) { if (e.code === 'no-pem-block') return []; throw e; }
  return blocks.filter(function(b) { return b.label === 'CERTIFICATE'; })
               .map(function(b) { return pem.encode(b.der, 'CERTIFICATE'); });
}

/**
 * A certificate from PEM (its first CERTIFICATE block) or DER. Throws when it
 * is not one. The result:
 *   pem          the PEM text (cryptographic-formats', for PEM given: that block)
 *   cf           cryptographic-formats' x509.from_der
 *   subjectKey,  the names as one string each, equal when the names match
 *   issuerKey    (RFC 5280 §7.1, as OpenSSL compares them)
 *   ski, aki     the key identifiers, or null
 *   notBefore,   Dates
 *   notAfter
 *   publicKey()  a node:crypto KeyObject, made on first use (null when
 *                node:crypto cannot use the key)
 */
function readCert(input) {
  let der;
  // PEM: a string, or bytes that are its text ('-----BEGIN', as a file read
  // gives it); other bytes are DER
  let text = typeof input === 'string' ? input
    : input instanceof Uint8Array && input[0] === 0x2d ? Buffer.from(input).toString('latin1') : null;
  if (text !== null) input = text;
  if (typeof input === 'string') {
    let pems = certificatePems(input);
    if (!pems.length) throw new Error('no CERTIFICATE block');
    der = pem.decode_one(pems[0], 'CERTIFICATE').der;
  } else {
    der = input;
  }
  let cf = x509.from_der(der);
  let ext = function(name) { let e = x509.extension(cf, name); return e ? e.parsed : null; };
  let key;
  return {
    pem: pem.encode(cf.der, 'CERTIFICATE'),
    cf: cf,
    subjectKey: x509.name_key(cf.subject),
    issuerKey: x509.name_key(cf.issuer),
    ski: ext('subjectKeyId'),
    aki: ext('authorityKeyId'),
    notBefore: cf.validity.not_before.date,
    notAfter: cf.validity.not_after.date,
    publicKey: function() {
      if (key === undefined) {
        try { key = keys.publicKey(cf.public_key); } catch (e) { key = null; }
        if (key && !key.spki) key = null;   // a kind keys.js does not read
      }
      return key;
    },
  };
}

/** A public key's SPKI DER (keys.js: one encoding per key), in hex. */
function spkiHex(key) {
  return Buffer.from(key.spki).toString('hex');
}

/**
 * Could `issuer` have issued `cert`? Its subject is the certificate's issuer
 * name, and where the certificate's authorityKeyIdentifier names a key
 * identifier, a serial or an issuer, the candidate is that one (OpenSSL's
 * X509_check_akid). Not the signature (signedBy).
 */
function issuedBy(cert, issuer) {
  if (cert.issuerKey !== issuer.subjectKey) return false;
  let aki = cert.aki;
  if (!aki) return true;
  if (aki.key_id && issuer.ski && !bytesEqual(aki.key_id, issuer.ski)) return false;
  if (aki.serial && !bytesEqual(aki.serial, issuer.cf.serial)) return false;
  if (aki.issuer) {
    let dns = aki.issuer.filter(function(g) { return g.type === 'directory'; });
    if (dns.length > 0 && !dns.some(function(g) { return x509.name_key(g.value) === issuer.issuerKey; })) return false;
  }
  return true;
}

/**
 * Is `cert`'s signature by `signerCert`'s key? The algorithm as cryptographic-formats
 * describes it, checked by cryptographic-primitives (keys.js). One it cannot
 * check — DSA, MD2 — does not verify; nor PKCS#1 v1.5 by an RSASSA-PSS key.
 */
function signedBy(cert, signerCert) {
  let key = signerCert.publicKey();
  if (!key) return false;
  let p = cert.cf.signature_params, tbs = cert.cf.tbs_bytes, sig = cert.cf.signature;
  switch (p.scheme) {
    case 'pkcs1': return keys.verify(key, { scheme: 'pkcs1', hash: p.hash }, tbs, sig);
    case 'pss':
      if (p.pss.mgf !== 'mgf1') return false;
      return keys.verify(key, { scheme: 'pss', hash: p.pss.hash, mgf_hash: p.pss.mgf_hash, salt_length: p.pss.salt_length }, tbs, sig);
    case 'ecdsa': return keys.verify(key, { scheme: 'ecdsa', hash: p.hash, form: 'der' }, tbs, sig);
    case 'eddsa': case 'ml-dsa': case 'slh-dsa': return keys.verify(key, { scheme: p.scheme }, tbs, sig);
    default: return false;
  }
}

/** Issued by itself, and signed by its own key. */
function selfSigned(cert) {
  return issuedBy(cert, cert) && signedBy(cert, cert);
}

export { certificatePems, readCert, spkiHex, issuedBy, signedBy, selfSigned };
