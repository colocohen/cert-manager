
import * as https from 'node:https';
import * as http from 'node:http';
import * as crypto from 'node:crypto';
import { signJws, getJwk } from './crypto.js';


/**
 * Fetch a URL.
 * callback(err, { status, headers, body, json })
 */
function httpRequest(url, method, headers, body, callback) {
  let parsed = new URL(url);
  let mod = parsed.protocol === 'https:' ? https : http;

  // RFC 8555 §6.1: ACME clients MUST send a User-Agent header
  if (!headers['User-Agent'] && !headers['user-agent']) {
    headers['User-Agent'] = 'acme-order/1.0';
  }

  let opts = {
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    path: parsed.pathname + parsed.search,
    method: method || 'GET',
    headers: headers || {},
  };

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

      callback(null, result);
    });
  });

  req.on('error', function(err) { callback(err); });

  if (body) {
    req.write(body);
  }
  req.end();
}


/**
 * ACME HTTP Client.
 * All methods use callback(err, result) pattern.
 */
function AcmeHttp(directory_url) {
  if (!(this instanceof AcmeHttp)) return new AcmeHttp(directory_url);

  let self = this;

  let directory = null;
  let nonce = null;


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
    });
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
    });
  };


  /**
   * Signed POST request to an ACME endpoint.
   * callback(err, res)
   */
  self.signedRequest = function(url, payload, account_key_pem, account_url, callback) {
    self.getNonce(function(err, current_nonce) {
      if (err) return callback(err);

      let protected_header = {
        alg: getAlgFromKey(account_key_pem),
        nonce: current_nonce,
        url: url,
      };

      if (account_url) {
        protected_header.kid = account_url;
      } else {
        protected_header.jwk = getJwk(account_key_pem);
      }

      let jws = signJws(payload, protected_header, account_key_pem);
      let body = JSON.stringify(jws);

      httpRequest(url, 'POST', {
        'Content-Type': 'application/jose+json',
        'Content-Length': Buffer.byteLength(body),
      }, body, function(err2, res) {
        if (err2) return callback(err2);

        // Save nonce for next request
        if (res.headers['replay-nonce']) {
          nonce = res.headers['replay-nonce'];
        }

        // Handle badNonce — retry once (RFC 8555 §6.5)
        if (res.status === 400 && res.json && res.json.type === 'urn:ietf:params:acme:error:badNonce') {
          nonce = res.headers['replay-nonce'] || null;
          return self.signedRequest(url, payload, account_key_pem, account_url, callback);
        }

        callback(null, res);
      });
    });
  };


  self.getUrl = function(resource) {
    if (!directory) return null;
    return directory[resource] || null;
  };

  self.getDirectoryData = function() {
    return directory;
  };
}


/**
 * Determine JWS algorithm from key PEM.
 */
function getAlgFromKey(pem) {
  let key = crypto.createPrivateKey(pem);

  if (key.asymmetricKeyType === 'ec') {
    let jwk = key.export({ format: 'jwk' });
    if (jwk.crv === 'P-384') return 'ES384';
    if (jwk.crv === 'P-521') return 'ES512';
    return 'ES256';
  }

  return 'RS256';
}


export { AcmeHttp, httpRequest };
