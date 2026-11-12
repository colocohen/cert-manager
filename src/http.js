
import * as https from 'node:https';
import * as http from 'node:http';
import { signJws } from './crypto.js';
import { loadKey } from './signer.js';


/**
 * Fetch a URL.
 * callback(err, { status, headers, body, json })
 */
function httpRequest(url, method, headers, body, callback, options) {
  options = options || {};
  let timeout = options.timeout || 30000;

  let parsed = new URL(url);
  let mod = parsed.protocol === 'https:' ? https : http;

  // Clone — never mutate the caller's headers object, and tolerate null
  headers = Object.assign({}, headers || {});

  // RFC 8555 §6.1: ACME clients MUST send a User-Agent header
  if (!headers['User-Agent'] && !headers['user-agent']) {
    headers['User-Agent'] = 'acme-order/1.0';
  }

  let opts = {
    // WHATWG URL keeps IPv6 brackets in .hostname ('[2a02::1]') — but
    // net.connect/http.request need the bare address, otherwise the literal
    // bracketed string goes to DNS and fails with ENOTFOUND. This silently
    // broke every IPv6 http-01 self-check.
    hostname: parsed.hostname.replace(/^\[|\]$/g, ''),
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    path: parsed.pathname + parsed.search,
    method: method || 'GET',
    headers: headers,
  };

  // Guard against double callback (timeout destroy + error event)
  let finished = false;
  function finish(err, res) {
    if (finished) return;
    finished = true;
    callback(err, res);
  }

  let req = mod.request(opts, function(res) {
    let chunks = [];
    res.on('data', function(chunk) { chunks.push(chunk); });
    res.on('end', function() {
      let raw = Buffer.concat(chunks);
      let result = {
        status: res.statusCode,
        headers: res.headers,
        body: raw,
        json: null,
      };

      let content_type = res.headers['content-type'] || '';
      if (content_type.indexOf('json') >= 0) {
        try {
          result.json = JSON.parse(raw.toString('utf8'));
        } catch(e) {}
      }

      finish(null, result);
    });
  });

  req.on('error', function(err) { finish(err); });

  // Abort requests that hang — a stuck socket must never block the flow forever
  req.setTimeout(timeout, function() {
    req.destroy(new Error('Request timed out after ' + timeout + 'ms: ' + method + ' ' + url));
  });

  if (body) {
    req.write(body);
  }
  req.end();
}


/**
 * ACME HTTP Client.
 * All methods use callback(err, result) pattern.
 */
function AcmeHttp(directory_url, options) {
  if (!(this instanceof AcmeHttp)) return new AcmeHttp(directory_url, options);
  options = options || {};

  let self = this;

  let directory = null;
  let nonce = null;

  let http_opts = { timeout: options.timeout || 30000 };
  let max_nonce_retries = options.maxNonceRetries || 3;


  /**
   * Fetch the ACME directory.
   * callback(err, directory)
   */
  self.getDirectory = function(callback) {
    httpRequest(directory_url, 'GET', {}, null, function(err, res) {
      if (err) return callback(err);
      if (res.status !== 200) return callback(new Error('Failed to fetch directory: HTTP ' + res.status));

      directory = res.json;
      if (res.headers['replay-nonce']) nonce = res.headers['replay-nonce'];

      callback(null, directory);
    }, http_opts);
  };


  /**
   * Get a fresh nonce.
   * callback(err, nonce_string)
   */
  self.getNonce = function(callback) {
    if (nonce !== null) {
      let n = nonce;
      nonce = null;
      return callback(null, n);
    }

    if (!directory || !directory.newNonce) {
      return callback(new Error('Directory not loaded'));
    }

    httpRequest(directory.newNonce, 'HEAD', {}, null, function(err, res) {
      if (err) return callback(err);
      callback(null, res.headers['replay-nonce'] || null);
    }, http_opts);
  };


  /**
   * Signed POST request to an ACME endpoint.
   * Retries on badNonce (RFC 8555 §6.5) up to max_nonce_retries times — never infinitely.
   * callback(err, res)
   */
  //
  // account_key: a PEM private key string, a signer { publicKey, sign }, or
  // a key already loaded by signer.loadKey (what Order passes - loaded once,
  // not re-parsed per request). The signature may take a while, or be
  // refused: the callback then gets the signer's error (err.code SIGN_*),
  // and nothing is sent.
  //
  // A badNonce retry signs AGAIN, over the new nonce - re-sending the old
  // body would only be refused again. With a remote signer that is one more
  // signature, which is why retries stay bounded.
  self.signedRequest = function(url, payload, account_key, account_url, callback) {
    let key;
    try {
      key = loadKey(account_key, { use: 'account' });
    } catch (e) {
      return setImmediate(callback, e);
    }
    signedAttempt(url, payload, key, account_url, 0, callback);
  };

  function signedAttempt(url, payload, key, account_url, attempt, callback) {
    self.getNonce(function(err, current_nonce) {
      if (err) return callback(err);

      let protected_header = {
        alg: key.alg.jws,
        nonce: current_nonce,
        url: url,
      };

      if (account_url) {
        protected_header.kid = account_url;
      } else {
        protected_header.jwk = key.jwk;
      }

      signJws(payload, protected_header, key, function(serr, jws) {
        if (serr) return callback(serr);
        send(JSON.stringify(jws));
      });
    });

    function send(body) {
      httpRequest(url, 'POST', {
        'Content-Type': 'application/jose+json',
        'Content-Length': Buffer.byteLength(body),
      }, body, function(err2, res) {
        if (err2) return callback(err2);

        // Save nonce for next request
        if (res.headers['replay-nonce']) {
          nonce = res.headers['replay-nonce'];
        }

        // Handle badNonce — bounded retry (a broken CA must not cause an infinite loop)
        if (res.status === 400 && res.json && res.json.type === 'urn:ietf:params:acme:error:badNonce') {
          nonce = res.headers['replay-nonce'] || null;
          if (attempt >= max_nonce_retries) {
            return callback(new Error('badNonce persisted after ' + max_nonce_retries + ' retries: ' + url));
          }
          return signedAttempt(url, payload, key, account_url, attempt + 1, callback);
        }

        callback(null, res);
      }, http_opts);
    }
  }


  self.getUrl = function(resource) {
    if (!directory) return null;
    return directory[resource] || null;
  };

  self.getDirectoryData = function() {
    return directory;
  };
}


export { AcmeHttp, httpRequest };
