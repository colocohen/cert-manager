import { EventEmitter } from 'node:events';
import * as https from 'node:https';
import * as keys from './keys.js';
import * as net from 'node:net';
import { cms, csr as csrFormat, pem } from 'cryptographic-formats';
import { generateKey, createCsr, pemEncode, canonicalIp, getCertDates, csrToDer } from './crypto.js';
import { loadKey, isSigner } from './signer.js';
import { readCert, spkiHex, issuedBy, signedBy, selfSigned as isSelfSigned } from './certs.js';
import { resolveProvider } from './providers.js';


// An order over EST (RFC 7030) - what createOrder() returns for
// provider: { est: url }. The same options where they apply (domain,
// altNames, keys, CSR), the same 'certificate' and 'error' events, the same
// methods; no challenges - the client proves who it is with a password or a
// certificate (auth), or, renewing, with the certificate it already has.
//
//   provider: { est: 'https://est.example.com', label?, ca? }
//   auth:     { username, password } and/or { clientCert, clientKey }
//   renew:    { cert, key }   - simplereenroll with the current certificate;
//                               refused, and auth is given → simpleenroll
//
// Events: 'pending' ({ retryAfter, attempt }) while the CA decides (a 202),
// 'certificate' (cert), 'error' (err, step).

// What only ACME has - refused by name, not ignored.
let ACME_ONLY = {
  challengeType: 'EST has no challenges - the client proves who it is with auth',
  eab: 'eab is ACME external account binding - EST authenticates with auth',
  accountKey: 'EST has no account - it authenticates with auth',
  accountUrl: 'EST has no account',
  profile: 'with EST, the CA label chooses the profile: provider: { est, label }',
  replaces: 'replaces is ACME ARI - EST renews with renew: { cert, key }',
  staging: 'staging applies to named ACME providers',
};

function EstOrder(options) {
  if (!(this instanceof EstOrder)) return new EstOrder(options);
  options = options || {};
  const ev = new EventEmitter();

  let context = {
    state: 'new',
    domain: options.domain || null,
    altNames: options.altNames || [],
    wildcard: !!options.wildcard,
    email: options.email || null,
    csrFields: options.csrFields || {},
    privateKey: options.privateKey || null,
    csr: options.csr || null,
    keyType: options.keyType || 'ecdsa',
    keySize: options.keySize,
    keyCurve: options.keyCurve,
    auth: options.auth || null,
    renew: options.renew || null,
    pendingTimeout: options.pendingTimeout || 10 * 60 * 1000,
    timeout: options.timeout || 30000,
    signTimeout: options.signTimeout || 60000,
    signRetries: options.signRetries >= 0 ? options.signRetries : 2,
    aborted: false,
    timers: [],
    request: null,
    provider: null,
  };

  function emitError(err, step) {
    if (context.aborted) return;
    context.state = 'error';
    clearTimers();
    if (ev.listenerCount('error') > 0) ev.emit('error', err, step);
  }
  function clearTimers() {
    context.timers.forEach(clearTimeout);
    context.timers = [];
    if (context.request) { try { context.request.destroy(); } catch (e) {} context.request = null; }
  }
  function later(fn, ms) { context.timers.push(setTimeout(fn, ms)); }


  // --- HTTP: one EST request ---

  function url(operation) {
    let u = new URL(context.provider.server);
    let base = u.pathname.replace(/\/+$/, '');
    if (base.indexOf('/.well-known/est') < 0) base += '/.well-known/est';
    if (context.provider.label) base += '/' + encodeURIComponent(context.provider.label);
    u.pathname = base + '/' + operation;
    return u;
  }

  // tls: { cert, key } for TLS client authentication, or null
  function request(method, operation, body, tls, cb) {
    let u = url(operation);
    let headers = {};
    let auth = context.auth || {};
    if (auth.username != null) {
      headers.Authorization = 'Basic ' + Buffer.from(auth.username + ':' + (auth.password || '')).toString('base64');
    }
    if (body != null) {
      headers['Content-Type'] = 'application/pkcs10';
      headers['Content-Transfer-Encoding'] = 'base64';
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    let opts = {
      method: method, hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
      headers: headers, timeout: context.timeout,
      servername: net.isIP(u.hostname) ? undefined : u.hostname,
    };
    if (context.provider.ca) opts.ca = context.provider.ca;
    if (tls) { opts.cert = tls.cert; opts.key = tls.key; }
    let done = false;
    function finish(err, res) { if (done) return; done = true; context.request = null; cb(err, res); }
    let req = https.request(opts, function(res) {
      let chunks = [];
      res.on('data', function(c) { chunks.push(c); });
      res.on('end', function() { finish(null, { status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }); });
      res.on('error', finish);
    });
    req.on('timeout', function() { req.destroy(new Error('EST ' + operation + ': no answer within ' + context.timeout + 'ms')); });
    req.on('error', finish);
    context.request = req;
    req.end(body != null ? body : undefined);
  }

  // RFC 7030 bodies are base64 (Content-Transfer-Encoding); some servers send DER
  function bodyDer(res) {
    let text = res.body.toString('latin1');
    if (/^[\sA-Za-z0-9+/=]+$/.test(text)) return new Uint8Array(Buffer.from(text.replace(/\s+/g, ''), 'base64'));
    return new Uint8Array(res.body);
  }

  function certsFromCms(res) {
    let der = bodyDer(res);
    let signed = cms.from_der(der);
    return (signed.certificates || []).map(function(c) { return pem.encode(c, 'CERTIFICATE'); });
  }

  function httpError(operation, res) {
    let detail = res.body.toString('utf8').trim().slice(0, 300);
    let err = new Error('EST ' + operation + ': HTTP ' + res.status + (detail ? ' - ' + detail : ''));
    err.status = res.status;
    if (res.status === 401) err.code = 'EST_UNAUTHORIZED';
    else if (res.status === 403) err.code = 'EST_FORBIDDEN';
    return err;
  }


  // --- the flow ---

  function names() {
    let alt = [];
    if (context.domain) alt.push(context.domain);
    if (context.wildcard) alt.push('*.' + context.domain);
    (context.altNames || []).forEach(function(n) { if (alt.indexOf(n) < 0) alt.push(n); });
    return alt;
  }

  function buildCsr(cb) {
    if (context.csr) {
      try { return cb(null, csrToDer(context.csr)); }
      catch (e) { return cb(new Error('csr is not a PEM CERTIFICATE REQUEST or DER bytes: ' + e.message)); }
    }
    let extra = context.csrFields;
    let opts = { commonName: context.domain, altNames: names(), emailAddress: context.email,
                 signTimeout: context.signTimeout, signRetries: context.signRetries };
    ['country', 'state', 'locality', 'organization', 'organizationUnit'].forEach(function(k) { if (extra[k]) opts[k] = extra[k]; });
    createCsr(opts, context.privateKey, cb);
  }

  // The CSR's public key in one encoding (keys.js) — the form the
  // certificate's is compared in, so two encodings of one key are equal
  function spkiOfCsr(der) {
    let parsed = csrFormat.from_der(der);
    return spkiHex(keys.publicKey(parsed.public_key));
  }

  // The chain to send with the certificate: from its issuer up, through the
  // CA certificates the server gave, stopping before a self-signed root
  // (that one belongs in trust stores). Where two certificates could issue
  // the next - a new root and its cross certificate, during a rotation -
  // the one that is not self-signed leads further, to the root clients
  // trusted longest.
  //
  // The certificates are read by cryptographic-formats (certs.js); a CA certificate
  // that does not read is no candidate. The chain is the certificates as
  // the server sent them.
  function buildChain(leafPem, caPems) {
    let pool = [];
    caPems.forEach(function(p) { try { pool.push({ text: p, cert: readCert(p) }); } catch (e) { /* not a candidate */ } });
    let chain = [];
    let current = readCert(leafPem);
    let issuerFound = false;
    // The certificates already on the path: one signed by one of their keys
    // leads back (the reverse cross certificate of a rotation) - a loop, not a chain
    let seen = [current];
    function signedBySeen(c) { return seen.some(function(s) { return signedBy(c, s); }); }
    for (let depth = 0; depth < 8; depth++) {
      let candidates = pool.filter(function(c) {
        return chain.indexOf(c.text) < 0 && issuedBy(current, c.cert) && signedBy(current, c.cert) &&
               (selfSigned(c) || !signedBySeen(c.cert));
      });
      if (!candidates.length) break;
      issuerFound = true;
      candidates.sort(function(a, b) { return selfSigned(a) - selfSigned(b); });
      let next = candidates[0];
      if (selfSigned(next)) break;
      chain.push(next.text);
      seen.push(next.cert);
      current = next.cert;
    }
    return { chain: chain, issued: issuerFound };
  }
  function selfSigned(c) { return isSelfSigned(c.cert) ? 1 : 0; }

  function run() {
    context.state = 'csr';
    buildCsr(function(err, csrDer) {
      if (context.aborted) return;
      if (err) return emitError(err, 'csr');
      context.csr = csrDer;

      context.state = 'cacerts';
      request('GET', 'cacerts', null, null, function(cerr, res) {
        if (context.aborted) return;
        if (cerr) return emitError(cerr, 'cacerts');
        if (res.status !== 200) return emitError(httpError('cacerts', res), 'cacerts');
        let caPems;
        try { caPems = certsFromCms(res); } catch (e) { return emitError(new Error('EST cacerts: not a certs-only CMS: ' + e.message), 'cacerts'); }
        if (!caPems.length) return emitError(new Error('EST cacerts: no CA certificates'), 'cacerts');
        enroll(caPems);
      });
    });
  }

  function enroll(caPems) {
    let body = Buffer.from(context.csr).toString('base64').replace(/(.{64})/g, '$1\n') + '\n';
    let started = Date.now();
    let attempt = 0;

    // Renewing with the current certificate needs its key here: Node's TLS
    // signs the handshake itself. A key held by a signer cannot - then the
    // renewal goes as a new enrollment, authenticated by auth.
    let renewTls = context.renew && context.renew.cert && context.renew.key && !isSigner(context.renew.key)
      ? { cert: context.renew.cert, key: context.renew.key } : null;
    let hasAuth = !!(context.auth && (context.auth.username != null || (context.auth.clientCert && context.auth.clientKey)));
    let authTls = context.auth && context.auth.clientCert && context.auth.clientKey
      ? { cert: context.auth.clientCert, key: context.auth.clientKey } : null;
    if (context.renew && !renewTls && !hasAuth) {
      return emitError(new Error('renew: the current key is a signer (it cannot authenticate TLS here) - give auth to enroll anew'), 'enroll');
    }

    let operation = renewTls ? 'simplereenroll' : 'simpleenroll';
    let tls = renewTls || authTls;

    function send() {
      context.state = 'enroll';
      request('POST', operation, body, tls, function(err, res) {
        if (context.aborted) return;
        if (err) return emitError(err, 'enroll');
        if (res.status === 202) {
          let ra = parseInt(res.headers['retry-after'], 10);
          let wait = (ra > 0 ? Math.min(ra, 3600) : 30) * 1000;
          if (Date.now() - started + wait > context.pendingTimeout) {
            return emitError(new Error('EST ' + operation + ': still pending after ' + Math.round((Date.now() - started) / 1000) + 's (pendingTimeout)'), 'pending');
          }
          attempt++;
          context.state = 'pending';
          ev.emit('pending', { retryAfter: Math.round(wait / 1000), attempt: attempt });
          return later(send, wait);
        }
        if (res.status !== 200) {
          // The current certificate refused (revoked, other names, policy):
          // enroll anew with auth, when there is some
          if (operation === 'simplereenroll' && hasAuth && res.status >= 400 && res.status < 500) {
            operation = 'simpleenroll';
            tls = authTls;
            return send();
          }
          return emitError(httpError(operation, res), 'enroll');
        }
        let certs;
        try { certs = certsFromCms(res); } catch (e) { return emitError(new Error('EST ' + operation + ': not a certs-only CMS: ' + e.message), 'enroll'); }
        if (!certs.length) return emitError(new Error('EST ' + operation + ': no certificate in the response'), 'enroll');
        deliver(certs[0], caPems, operation);
      });
    }
    send();
  }

  function deliver(leafPem, caPems, via) {
    context.state = 'certificate';
    try {
      // The certificate is for the key in our CSR...
      let leaf = readCert(leafPem);
      let leafKey = leaf.publicKey();
      if (!leafKey || spkiHex(leafKey) !== spkiOfCsr(context.csr)) throw new Error('the certificate is not for the key in the CSR');
      // ...and was issued by the CA the server named
      let built = buildChain(leafPem, caPems);
      if (!built.issued) throw new Error('the certificate was not issued by any of the CA certificates the server gave (cacerts)');
      let dates = getCertDates(leafPem);
      let cert = {
        cert: leafPem,
        ca: built.chain,
        cacerts: caPems,
        key: isSigner(context.privateKey) ? null : context.privateKey,
        csr: pemEncode(context.csr, 'CERTIFICATE REQUEST'),
        expiresAt: dates ? dates.expires : null,
        via: via,
      };
      context.cert = cert;
      context.state = 'done';
      ev.emit('certificate', cert);
    } catch (e) {
      emitError(new Error('EST ' + via + ': ' + e.message), 'certificate');
    }
  }


  let api = {
    context: context,
    on: function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },
    once: function(name, fn) { ev.once(name, fn); },

    start: function() {
      if (context.aborted || context.state !== 'new') return;
      let problems = [];
      try {
        context.provider = resolveProvider(options.provider, options.staging);
      } catch (e) { problems.push(e.message); }
      Object.keys(ACME_ONLY).forEach(function(k) {
        if (options[k] != null && options[k] !== false) problems.push(k + ': ' + ACME_ONLY[k]);
      });
      if (!context.domain && !context.csr) problems.push('domain (or csr) is required');
      if (context.domain && net.isIP(context.domain)) context.domain = canonicalIp(context.domain);
      context.altNames = (context.altNames || []).map(function(n) { return net.isIP(n) ? canonicalIp(n) : n; });
      if (context.auth && (!!context.auth.clientCert !== !!context.auth.clientKey)) problems.push('auth: clientCert and clientKey go together');
      if (context.renew && !(context.renew.cert && context.renew.key)) problems.push('renew: { cert, key }');
      if (context.privateKey !== null) {
        try { loadKey(context.privateKey, { use: 'certificate', signTimeout: context.signTimeout, signRetries: context.signRetries }); }
        catch (e) { problems.push(e.message); }
      }
      if (problems.length) {
        process.nextTick(function() { emitError(new Error('Invalid options: ' + problems.join('; ')), 'options'); });
        return;
      }
      if (context.privateKey === null && !context.csr) {
        context.privateKey = context.keyType === 'rsa'
          ? generateKey('rsa', { size: context.keySize })
          : generateKey('ecdsa', { curve: context.keyCurve });
      }
      process.nextTick(run);
    },

    abort: function() {
      let step = context.state;
      context.aborted = true;
      clearTimers();
      context.state = 'aborted';
      ev.emit('abort', step);
    },

    getState: function() { return context.state; },
    getDomain: function() { return context.domain; },
    getProfile: function() { return context.provider ? context.provider.label : (options.provider && options.provider.label) || null; },
    getChallengeType: function() { return null; },
    getAccountKey: function() { return null; },
    getPrivateKey: function() { return context.privateKey; },
    getCsr: function() { return context.csr; },
    getCsrPem: function() { return context.csr ? pemEncode(context.csr, 'CERTIFICATE REQUEST') : null; },
  };

  for (let k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }
  if (options.autoStart === true) {
    let self = this;
    process.nextTick(function() { self.start(); });
  }
  return this;
}

export default EstOrder;
