/**
 * Keys: read by cryptographic-formats (PEM, PKCS#8, SEC 1, PKCS#1, SPKI,
 * JWK), signed and verified by cryptographic-primitives — the library picks
 * native or pure JavaScript.
 *
 *   privateKey(input)   a PEM private key (string or Buffer) or its DER:
 *                       { type, curve, spki, jwk, sign(hash, bytes, form) }
 *   publicKey(input)    SPKI PEM / DER, a public JWK, a parsed SPKI, or a
 *                       node:crypto KeyObject: { type, curve, bits, spki, jwk,
 *                       verify(how, bytes, sig) }
 *
 * type is 'ec' or 'rsa' (EdDSA, ML-DSA and SLH-DSA public keys verify too, for
 * certificate chains), curve the JWK name ('P-256'); spki the key's SPKI
 * DER in one encoding per key (an EC point uncompressed), so two encodings
 * of one key compare equal; jwk the public JWK. A signature is 'raw' (JOSE's
 * r||s) or 'der' (X.509's) for ECDSA, the bytes for RSA (PKCS#1 v1.5).
 */

import * as PEM from 'cryptographic-formats/pem';
import * as PKCS8 from 'cryptographic-formats/pkcs8';
import * as SPKI from 'cryptographic-formats/spki';
import * as JWK from 'cryptographic-formats/jwk';
import * as SIG from 'cryptographic-formats/signature';
import { p256, p384, p521 } from 'cryptographic-primitives/nist.js';
import * as RSA from 'cryptographic-primitives/rsa.js';
import * as ED25519 from 'cryptographic-primitives/ed25519.js';
import * as ED448 from 'cryptographic-primitives/ed448.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from 'cryptographic-primitives/ml_dsa.js';
import * as SLH from 'cryptographic-primitives/slh_dsa.js';
import { sha1_sync } from 'cryptographic-primitives/sha1.js';
import { sha224_sync, sha256_sync, sha384_sync, sha512_sync } from 'cryptographic-primitives/sha2.js';

const HASH = { sha1: sha1_sync, sha224: sha224_sync, sha256: sha256_sync, sha384: sha384_sync, sha512: sha512_sync };
const HASH_LEN = { sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64 };

// cryptographic-formats's curve name: the library's curve, the JWK name, the
// width of r and s.
const CURVES = {
  secp256r1: [p256, 'P-256', 32], secp384r1: [p384, 'P-384', 48], secp521r1: [p521, 'P-521', 66],
};
const OTHER = { Ed25519: [ED25519, 'ed25519'], Ed448: [ED448, 'ed448'],
                mlDsa44: [ml_dsa44, 'ml-dsa-44'], mlDsa65: [ml_dsa65, 'ml-dsa-65'], mlDsa87: [ml_dsa87, 'ml-dsa-87'] };

// cryptographic-formats's SLH-DSA name (slhDsaSha2_128s): the library's
// parameter set, and node:crypto's key type (slh-dsa-sha2-128s).
function slh(alg) {
  let m = /^slhDsa(Sha2|Shake)_(\d+[sf])$/.exec(alg || '');
  if (!m) return null;
  let lib = SLH['slh_dsa_' + m[1].toLowerCase() + '_' + m[2]];
  return lib ? [lib, 'slh-dsa-' + m[1].toLowerCase() + '-' + m[2]] : null;
}

function big(bytes) {
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}
function bytes_of(n, width) {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  let b = Buffer.from(h, 'hex');
  let out = new Uint8Array(width && width > b.length ? width : b.length);
  out.set(b, out.length - b.length);
  return out;
}
function bit_length(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  if (i === bytes.length) return 0;
  return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
}
function strip(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  return bytes.subarray(i);
}

// The public half of a parsed key (SPKI, PKCS#8 or JWK, one shape in
// cryptographic-formats): its fields, its SPKI in one encoding, its JWK.
function describe(p) {
  let k = { type: null, curve: null, bits: 0, spki: null, jwk: null };
  let c, o;
  if (p.algorithm === 'ecPublicKey' && (c = CURVES[p.curve])) {
    let point = p.point;
    if (point && point[0] !== 0x04) point = uncompressed(c[0], point);
    k.type = 'ec';
    k.curve = c[1];
    k.width = c[2];
    k.lib = c[0];
    k.point = point;
    k.spki = SPKI.to_der({ algorithm: 'ecPublicKey', curve: p.curve, point: point });
    k.jwk = public_jwk(JWK.from_key({ algorithm: 'ecPublicKey', curve: p.curve, point: point }));
  } else if (p.algorithm === 'rsassaPss' && p.rsa) {
    // An RSASSA-PSS key (RFC 4055): it verifies PSS only; its SPKI as given.
    let n = strip(p.rsa.n);
    k.type = 'rsa-pss';
    k.bits = bit_length(n);
    k.rsa = { n: big(n), e: big(strip(p.rsa.e)) };
    k.spki = p.der || SPKI.to_der(p);
  } else if (p.algorithm === 'rsaEncryption') {
    let n = strip(p.rsa.n), e = strip(p.rsa.e);
    k.type = 'rsa';
    k.bits = bit_length(n);
    k.rsa = { n: big(n), e: big(e) };
    k.spki = SPKI.to_der({ algorithm: 'rsaEncryption', rsa: { n: n, e: e } });
    k.jwk = public_jwk(JWK.from_key({ algorithm: 'rsaEncryption', rsa: { n: n, e: e } }));
  } else if ((o = OTHER[p.algorithm] || slh(p.algorithm))) {
    k.type = o[1];
    k.lib = o[0];
    k.raw = p.point;
    k.spki = SPKI.to_der({ algorithm: p.algorithm, point: p.point });
  } else {
    k.type = p.algorithm || null;
  }
  return k;
}
// A compressed EC point, uncompressed: decoded by the library (x, y), then
// written 04 || x || y.
function uncompressed(curve, point) {
  let xy = curve.decode_point_sync(point);
  let w = point.length - 1;
  let out = new Uint8Array(1 + 2 * w);
  out[0] = 0x04;
  out.set(bytes_of(xy.x, w), 1);
  out.set(bytes_of(xy.y, w), 1 + w);
  return out;
}
// The public members only (RFC 7638's set for a thumbprint, and what ACME
// sends), in the order node:crypto's export gave them.
function public_jwk(j) {
  if (j.kty === 'EC') return { kty: 'EC', crv: j.crv, x: j.x, y: j.y };
  return { kty: 'RSA', n: j.n, e: j.e };
}

/* ---------------------------------------------------------------- public */

/**
 * A public key from SPKI PEM text, SPKI DER, a public JWK, a parsed SPKI,
 * or a node:crypto KeyObject (its SPKI). Throws on anything else, and on a
 * private JWK (one with "d").
 */
function publicKey(input) {
  let p;
  if (input && typeof input === 'object' && typeof input.export === 'function' && typeof input.asymmetricKeyType === 'string') {
    p = SPKI.from_der(new Uint8Array(input.export({ type: 'spki', format: 'der' })));   // a KeyObject, private or public
  } else if (typeof input === 'string' || (Buffer.isBuffer(input) && looks_pem(input))) {
    let blocks = PEM.decode(String(input));
    let b = blocks.filter(function (x) { return x.label === 'PUBLIC KEY'; })[0];
    if (!b) throw new Error('no PUBLIC KEY in the PEM (' + blocks.map(function (x) { return x.label; }).join(', ') + ')');
    p = SPKI.from_der(b.der);
  } else if (input instanceof Uint8Array) {
    p = SPKI.from_der(input);
  } else if (input && typeof input === 'object' && typeof input.kty === 'string') {
    if (input.d !== undefined) {
      // A private JWK handed over as "the public key" would put the secret
      // into account.json and into every newAccount request.
      throw new Error('publicKey is a PRIVATE JWK (it has "d") - pass the public members only');
    }
    p = JWK.to_key(input);
  } else if (input && typeof input === 'object' && typeof input.algorithm === 'string') {
    p = input;
  } else {
    throw new Error('publicKey must be SPKI PEM, SPKI DER bytes, a JWK, or a KeyObject');
  }
  let k = describe(p);
  k.verify = function (how, bytes, sig) { return verify(k, how, bytes, sig); };
  return k;
}

/**
 * Whether `sig` is `key`'s signature over `bytes`. how: { scheme: 'ecdsa' |
 * 'pkcs1' | 'pss' | 'eddsa' | 'ml-dsa' | 'slh-dsa', hash, form: 'raw' | 'der' (ECDSA),
 * salt_length, mgf_hash (PSS) }. False, never a throw, for anything that is
 * not a valid signature.
 */
function verify(key, how, bytes, sig) {
  try {
    switch (how.scheme) {
      case 'ecdsa': {
        if (key.type !== 'ec' || !HASH[how.hash]) return false;
        let rs;
        if (how.form === 'raw') {
          if (sig.length !== 2 * key.width) return false;
          rs = { r: big(sig.subarray(0, key.width)), s: big(sig.subarray(key.width)) };
        } else {
          let p = SIG.parse_der({ der: sig });
          rs = { r: big(p.r), s: big(p.s) };
        }
        return key.lib.verify_message_sync(HASH[how.hash], bytes, rs, key.point) === true;
      }
      case 'pkcs1':
        return key.type === 'rsa' && !!HASH[how.hash] && RSA.verify_pkcs1_message_sync(key.rsa, bytes, sig, HASH[how.hash]) === true;
      case 'pss': {
        if ((key.type !== 'rsa' && key.type !== 'rsa-pss') || !HASH[how.hash] || !HASH[how.mgf_hash || how.hash]) return false;
        let salt = how.salt_length != null ? how.salt_length : HASH_LEN[how.hash];
        return RSA.verify_pss_message_sync(key.rsa, bytes, sig, HASH[how.hash], salt, HASH[how.mgf_hash || how.hash]) === true;
      }
      case 'eddsa': return (key.type === 'ed25519' || key.type === 'ed448') && key.lib.verify_sync(bytes, sig, key.raw, undefined, 'strict') === true;
      case 'ml-dsa': return /^ml-dsa/.test(key.type) && key.lib.verify_sync(key.raw, bytes, sig) === true;
      case 'slh-dsa': return /^slh-dsa/.test(key.type) && key.lib.verify_sync(key.raw, bytes, sig) === true;
      default: return false;
    }
  } catch (e) {
    return false;
  }
}

/* --------------------------------------------------------------- private */

const READERS = [PKCS8.from_der, PKCS8.sec1_from_der, PKCS8.pkcs1_from_der];
const PEM_LABELS = { 'PRIVATE KEY': PKCS8.from_der, 'EC PRIVATE KEY': PKCS8.sec1_from_der, 'RSA PRIVATE KEY': PKCS8.pkcs1_from_der };

function looks_pem(buf) {
  return buf.length > 0 && buf[0] !== 0x30;
}

/**
 * A private key from PEM text (a string or a Buffer holding it) or DER:
 * PKCS#8, SEC 1 or PKCS#1. sign(hash, bytes, form) signs `bytes` with the
 * hash ('sha256', ...): ECDSA as 'raw' or 'der', RSA with PKCS#1 v1.5.
 * Throws on a key it cannot read, an encrypted one among them.
 */
function privateKey(input) {
  let p = null;
  if (typeof input === 'string' || (Buffer.isBuffer(input) && looks_pem(input))) {
    let blocks = PEM.decode(String(input));
    for (let i = 0; i < blocks.length && !p; i++) {
      if (blocks[i].encrypted || blocks[i].label === 'ENCRYPTED PRIVATE KEY') throw new Error('the private key is encrypted');
      if (PEM_LABELS[blocks[i].label]) p = PEM_LABELS[blocks[i].label](blocks[i].der);
    }
    if (!p) throw new Error('no private key in the PEM (' + blocks.map(function (b) { return b.label; }).join(', ') + ')');
  } else if (input instanceof Uint8Array) {
    for (let i = 0; i < READERS.length && !p; i++) { try { p = READERS[i](input); } catch (e) { /* the next */ } }
    if (!p) throw new Error('the key is not PKCS#8, SEC 1 or PKCS#1 DER');
  } else {
    throw new Error('expected a PEM private key');
  }
  let pub;
  if (p.algorithm === 'ecPublicKey' && CURVES[p.curve]) {
    pub = { algorithm: 'ecPublicKey', curve: p.curve, point: p.point || CURVES[p.curve][0].get_public_key_sync(p.scalar, false) };
  } else if (p.algorithm === 'rsaEncryption') {
    pub = { algorithm: 'rsaEncryption', rsa: { n: p.rsa.n, e: p.rsa.e } };
  } else if (OTHER[p.algorithm] && (p.algorithm === 'Ed25519' || p.algorithm === 'Ed448')) {
    pub = { algorithm: p.algorithm, point: OTHER[p.algorithm][0].get_public_key_sync(p.scalar) };
  } else {
    pub = { algorithm: p.algorithm };
  }
  let k = describe(pub);
  let signer = null;
  k.sign = function (hash, bytes, form) {
    if (!HASH[hash]) throw new Error('unsupported hash ' + hash);
    if (k.type === 'ec') {
      if (!signer) signer = k.lib.signer_create(p.scalar);
      let rs = signer.sign_message_sync(HASH[hash], bytes);
      if (form === 'raw') {
        let out = new Uint8Array(2 * k.width);
        out.set(bytes_of(rs.r, k.width), 0);
        out.set(bytes_of(rs.s, k.width), k.width);
        return out;
      }
      return SIG.from_pair({ r: bytes_of(rs.r), s: bytes_of(rs.s) });
    }
    if (k.type === 'rsa') {
      if (!signer) {
        let r = p.rsa;
        signer = RSA.signer_create({ n: big(r.n), e: big(r.e), d: big(r.d), p: big(r.p), q: big(r.q),
                                     dp: big(r.dp), dq: big(r.dq), qinv: big(r.qinv) });
      }
      return signer.sign_pkcs1_message_sync(bytes, HASH[hash]);
    }
    throw new Error('cannot sign with a ' + k.type + ' key');
  };
  return k;
}

export { privateKey, publicKey, verify };
