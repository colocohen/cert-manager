
import { signature, jwk as jwkFormat } from 'cryptographic-formats';
import { sha256_sync } from 'cryptographic-primitives/sha2.js';
import * as keys from './keys.js';


/**
 * Keys, whatever holds them.
 *
 * Every place that takes a private key (accountKey, privateKey) takes one of:
 *
 *   - a PEM string - the key is here, and cryptographic-primitives signs with it
 *                    (keys.js);
 *   - a signer     - the key is somewhere else (an HSM, a cloud KMS, a remote
 *                    or threshold signing service),
 *                    and this library only ever sees the public key:
 *
 *       {
 *         publicKey,                  // SPKI PEM / DER, or a JWK
 *         algorithm,                  // optional: 'ES256' / 'ecdsaWithSHA256' / 'RS256' ...
 *         sign: function (bytes, cb), // cb(err, signature) - may be slow, may refuse
 *         signatureFormat             // ECDSA only: 'raw' (r||s) or 'der'
 *       }
 *
 * loadKey() turns either into one shape, so the ACME flow never asks which
 * it has. Signing is always asynchronous - even with a PEM key the callback
 * comes on a later tick - because the order's state machine must never be
 * re-entered from inside one of its own passes (see the note in order.js).
 */


// What a key can sign with, by key type. `jws` is the JOSE name ACME's
// protected header carries; `x509` the AlgorithmIdentifier a CSR carries;
// `curve` the name cryptographic-formats' signature module uses for r||s widths.
let EC_ALGS = {
  'P-256': { jws: 'ES256', x509: 'ecdsaWithSHA256', hash: 'sha256', curve: 'secp256r1' },
  'P-384': { jws: 'ES384', x509: 'ecdsaWithSHA384', hash: 'sha384', curve: 'secp384r1' },
  'P-521': { jws: 'ES512', x509: 'ecdsaWithSHA512', hash: 'sha512', curve: 'secp521r1' },
};
let RSA_ALG = { jws: 'RS256', x509: 'sha256WithRSAEncryption', hash: 'sha256', curve: null };

let DEFAULT_SIGN_TIMEOUT = 60000;
let DEFAULT_SIGN_RETRIES = 2;


function isSigner(k) {
  return !!k && typeof k === 'object' && typeof k.sign === 'function';
}


// An error the caller can tell apart by `code`, never by message:
//   KEY_INVALID     the key or signer description itself is wrong
//   SIGN_TIMEOUT    the signer did not answer in signTimeout (after retries)
//   SIGN_REJECTED   the signer answered with an error - a refusal, a policy
//                   decision, an outage; the signer's own error is `cause`
//   SIGN_INVALID    the signer answered with something that is not a valid
//                   signature by this key: wrong length, wrong format,
//                   another key
function keyError(code, message, cause) {
  let e = new Error(message);
  e.code = code;
  if (cause !== undefined) e.cause = cause;
  return e;
}


// What a key can sign with, from its type (keys.js): an ECDSA curve or RSA.
function algorithmsFor(publicKey) {
  let type = publicKey.type;
  if (type === 'ec') {
    let alg = EC_ALGS[publicKey.curve];
    if (!alg) throw new Error('unsupported EC curve: ' + publicKey.curve + ' (supported: P-256, P-384, P-521)');
    return alg;
  }
  if (type === 'rsa') {
    let bits = publicKey.bits;
    if (bits && bits < 2048) throw new Error('RSA key size must be at least 2048 bits (got ' + bits + ')');
    return RSA_ALG;
  }
  if (type === 'ed25519' || type === 'ed448') {
    // Let's Encrypt accepts neither for an account key (RFC 8555 names no
    // EdDSA) nor for a certificate key. Refuse here, not with a CA error.
    throw new Error(type + ' keys are not accepted by Let\'s Encrypt - use ECDSA (P-256/P-384) or RSA');
  }
  throw new Error('unsupported key type: ' + type + ' (supported: ec, rsa)');
}

/** The public JWK of a key (keys.js): only the public members, in RFC 7638's set. */
function publicJwk(key) {
  return key.jwk;
}

/**
 * RFC 7638 thumbprint of a public JWK, base64url - what ACME puts after the
 * token in every key authorization. cryptographic-formats supplies the canonical
 * bytes; the hash is cryptographic-primitives'.
 */
function jwkThumbprint(jwk) {
  let input = jwkFormat.thumbprint_input(jwk);
  return Buffer.from(sha256_sync(input)).toString('base64url');
}

function toBytes(x) {
  if (x instanceof Uint8Array) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  return null;
}


/**
 * Load a key for signing.
 *
 *   input   PEM private key string, or a signer object
 *   opts    { use: 'account' | 'certificate', signTimeout, signRetries }
 *
 * Throws KEY_INVALID with a precise message when the key cannot be used.
 * Returns:
 *   {
 *     loaded: true, signer: bool, source: input,
 *     publicKey (keys.js), spki (Uint8Array), jwk (public), thumbprint,
 *     alg: { jws, x509, hash, curve },
 *     sign(bytes, form, cb)   form 'raw' (JOSE) or 'der' (X.509); cb(err, Uint8Array)
 *   }
 */
function loadKey(input, opts) {
  opts = opts || {};
  if (input && input.loaded === true && typeof input.sign === 'function' && input.alg) return input;

  let use = opts.use || 'account';
  let what = use === 'account' ? 'accountKey' : 'privateKey';

  let privateKey = null;
  let publicKey = null;

  try {
    if (isSigner(input)) {
      if (input.publicKey == null) throw new Error('a signer needs publicKey');
      publicKey = keys.publicKey(input.publicKey);
    } else if (typeof input === 'string' || Buffer.isBuffer(input)) {
      privateKey = keys.privateKey(input);
      publicKey = privateKey;
    } else {
      throw new Error('expected a PEM private key or a signer { publicKey, sign }');
    }
  } catch (e) {
    throw keyError('KEY_INVALID', what + ': ' + e.message, e);
  }

  let alg;
  try { alg = algorithmsFor(publicKey); }
  catch (e) { throw keyError('KEY_INVALID', what + ': ' + e.message, e); }

  let signer = isSigner(input);
  let native_format = null;   // what the signer returns, for ECDSA

  if (signer) {
    // The algorithm, when stated, must be the one the key implies - a
    // signer that says ES384 over a P-256 key would sign with one hash
    // while every header claims the other.
    if (input.algorithm != null) {
      let a = String(input.algorithm);
      if (a !== alg.jws && a !== alg.x509) {
        throw keyError('KEY_INVALID', what + ": algorithm '" + a + "' does not match the public key (expected '" +
          alg.jws + "' or '" + alg.x509 + "')");
      }
    }
    if (alg.curve) {
      native_format = input.signatureFormat || (use === 'account' ? 'raw' : 'der');
      if (native_format !== 'raw' && native_format !== 'der') {
        throw keyError('KEY_INVALID', what + ": signatureFormat must be 'raw' or 'der' (got '" + native_format + "')");
      }
    }
  }

  let timeout = opts.signTimeout > 0 ? opts.signTimeout : DEFAULT_SIGN_TIMEOUT;
  let retries = (opts.signRetries >= 0) ? opts.signRetries : DEFAULT_SIGN_RETRIES;

  let spki = publicKey.spki;
  let jwk = publicKey.jwk;

  let key = {
    loaded: true,
    signer: signer,
    source: input,
    use: use,
    publicKey: publicKey,
    spki: spki,
    jwk: jwk,
    thumbprint: jwkThumbprint(jwk),
    alg: alg,
    sign: null,
  };

  // --- Local key: cryptographic-primitives (keys.js) ---
  function signLocal(bytes, form, cb) {
    let sig;
    try {
      sig = privateKey.sign(alg.hash, bytes, form);
    } catch (e) {
      return setImmediate(cb, keyError('SIGN_REJECTED', what + ': local signing failed: ' + e.message, e));
    }
    setImmediate(cb, null, sig);
  }

  // --- Signer: timeout, retries, format conversion, verification ---
  function signRemote(bytes, form, cb) {
    let attempt = 0;

    function run() {
      let settled = false;
      let timer = setTimeout(function() {
        if (settled) return;
        settled = true;
        // A late answer from this attempt is ignored: `settled` stays true.
        retryOr(keyError('SIGN_TIMEOUT', what + ': the signer did not answer within ' + timeout + 'ms'), true);
      }, timeout);
      // Deliberately not unref()'d: a pending signature is work in flight,
      // and the process must not exit under it because the signer's own
      // wait (a socket, a queue) happens not to hold the event loop.

      function answer(err, sig) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (err) {
          let e = (err instanceof Error) ? err : new Error(String(err));
          return retryOr(keyError('SIGN_REJECTED', what + ': the signer refused: ' + e.message, e), e.retryable === true);
        }
        finish(sig);
      }

      try {
        input.sign(new Uint8Array(bytes), answer);
      } catch (e) {
        answer(e);
      }
    }

    function retryOr(err, retryable) {
      if (retryable && attempt < retries) {
        attempt++;
        let delay = Math.min(1000 * Math.pow(2, attempt - 1), 30000);
        setTimeout(run, delay);
        return;
      }
      if (attempt > 0) err.attempts = attempt + 1;
      setImmediate(cb, err);
    }

    function finish(sig) {
      let raw = toBytes(sig);
      if (!raw) {
        return setImmediate(cb, keyError('SIGN_INVALID', what + ': the signer returned ' +
          (typeof sig) + ', not bytes (Uint8Array / Buffer)'));
      }

      let out = raw;
      if (alg.curve && native_format !== form) {
        try {
          out = form === 'raw'
            ? signature.der_to_raw({ der: raw, curve: alg.curve })
            : signature.raw_to_der({ raw: raw, curve: alg.curve });
        } catch (e) {
          return setImmediate(cb, keyError('SIGN_INVALID', what + ": the signer's answer is not a " +
            native_format + ' ECDSA signature (signatureFormat: ' + native_format + '): ' + e.message, e));
        }
      }

      // Verify before anything leaves: a signature by another key, or in the
      // other format, would otherwise come back from the CA as an opaque
      // badSignature - after a nonce, a request and a round trip were spent.
      let ok = publicKey.verify({ scheme: alg.curve ? 'ecdsa' : 'pkcs1', hash: alg.hash, form: form }, bytes, out);

      if (!ok) {
        return setImmediate(cb, keyError('SIGN_INVALID', what + ': the signature does not verify under publicKey ' +
          '(a different key signed, or signatureFormat is wrong)'));
      }
      setImmediate(cb, null, new Uint8Array(out));
    }

    run();
  }

  key.sign = function(bytes, form, cb) {
    if (form !== 'raw' && form !== 'der') throw new TypeError("sign form must be 'raw' or 'der'");
    if (signer) signRemote(bytes, form, cb);
    else signLocal(bytes, form, cb);
  };

  return key;
}


export {
  isSigner,
  loadKey,
  jwkThumbprint,
  publicJwk,
  keyError,
};
