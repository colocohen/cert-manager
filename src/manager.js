
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as path from 'node:path';
import Order from './order.js';
import { httpRequest, AcmeHttp } from './http.js';
import * as net from 'node:net';
import * as keys from './keys.js';
import { x509 } from 'cryptographic-formats';
import { readCert, certificatePems, spkiHex } from './certs.js';
import { getAriCertId, getCertDates, canonicalIp } from './crypto.js';
import { loadKey } from './signer.js';
import { resolveProvider } from './providers.js';


function Manager(options) {
  if (!(this instanceof Manager)) return new Manager(options);
  options = options || {};

  const ev = new EventEmitter();

  let config = {
    dir: options.dir || './certs',
    email: options.email || null,
    provider: options.provider || 'letsencrypt',
    staging: !!options.staging,
    eab: options.eab || null,

    // EST (provider: { est: url }): who this client is - { username,
    // password } and/or { clientCert, clientKey }. A renewal goes with the
    // current certificate first, and falls back to these.
    auth: options.auth || null,

    ari: options.ari !== false,   // ACME Renewal Information (RFC 9773)
    renewBeforeDays: options.renewBeforeDays || 7,
    checkInterval: options.checkInterval || 1000 * 60 * 10,
    retryInterval: options.retryInterval || 1000 * 60 * 60 * 4,

    // The ACME account key: a PEM string or a signer { publicKey, sign }.
    // Given here, it is never written to disk - account.json keeps only
    // the account URL and the public JWK. Not given: generated and stored
    // in account.json, as before.
    accountKey: options.accountKey || null,

    // The certificate's key, per name: function (domain, cb) calling
    // cb(null, signerOrPem) - or cb(null, null) for a fresh key, the
    // default. For keys held in an HSM; the key is then not in the
    // certificate's JSON file, and 'certificate' gives key: null.
    certKey: (typeof options.certKey === 'function') ? options.certKey : null,

    // One whole issuance, from account to certificate. Longer when a signer
    // may wait for a human approval.
    orderTimeout: options.orderTimeout || 1000 * 60 * 10,
    signTimeout: options.signTimeout || undefined,
    signRetries: options.signRetries,
  };

  // The provider, resolved once. One that cannot work leaves this null:
  // every order then reports it, as before.
  let provider_info = null;
  try { provider_info = resolveProvider(config.provider, config.staging); } catch (e) { provider_info = null; }
  let est = !!(provider_info && provider_info.protocol === 'est');

  // A configured accountKey that cannot work is a configuration error -
  // thrown at construction, not discovered at the first renewal.
  let account_key = null;
  if (config.accountKey) {
    account_key = loadKey(config.accountKey, { use: 'account' });
  }

  let check_timer = null;
  let current = null;
  let current_order = null;
  let current_timeout = null;   // per-domain 10-min timeout — module scope so stop() can clear it
  let stopped = false;          // stop() sets this; finish() must not reschedule afterwards
  let scanning = false;         // guards checkAll against overlapping async scans

  let CSV_HEADER = 'domain,status,issued_at,expires_at,renew_after,last_attempt,last_error';


  // Emit 'error' safely — a bare EventEmitter 'error' with no listener
  // crashes the process
  function emitError(domain, err) {
    if (ev.listenerCount('error') > 0) {
      ev.emit('error', domain, err);
    } else {
      console.error('[cert-manager] unhandled manager error for "' + domain + '":', err && err.message ? err.message : err);
    }
  }

  // One address, one row: '2A02::0001' and '2a02::1' must be the same key
  function normDomain(domain) {
    return (typeof domain === 'string' && net.isIP(domain)) ? canonicalIp(domain) : domain;
  }

  // Strip characters that would corrupt the CSV structure
  function csvSafe(value) {
    return String(value == null ? '' : value).replace(/[\r\n]+/g, ' ');
  }


  // --- File paths ---

  // IPv6 addresses contain ':' — illegal in Windows filenames and confusing
  // everywhere else. The CSV keeps the original identifier; only the JSON
  // filename is sanitized.
  function safeName(domain) {
    return String(domain).replace(/[^a-zA-Z0-9.\-_*]/g, '_').replace(/\*/g, '_');
  }

  function csvPath() { return path.join(config.dir, 'certificates.csv'); }
  function accountPath() { return path.join(config.dir, 'account.json'); }
  function certPath(domain) { return path.join(config.dir, safeName(domain) + '.json'); }


  // --- CSV helpers ---

  function parseCsvLine(line) {
    let cols = line.split(',');
    if (cols.length < 7) return null;
    return {
      domain: cols[0], status: cols[1], issued_at: cols[2],
      expires_at: cols[3], renew_after: cols[4],
      last_attempt: cols[5], last_error: cols.slice(6).join(','),
    };
  }

  function rowToCsv(r) {
    return [csvSafe(r.domain), csvSafe(r.status), csvSafe(r.issued_at), csvSafe(r.expires_at),
      csvSafe(r.renew_after), csvSafe(r.last_attempt), csvSafe(r.last_error)].join(',');
  }

  function readCsv(callback) {
    fs.readFile(csvPath(), 'utf8', function(err, data) {
      if (err) {
        // Only ENOENT means "no data yet". Any other error (EBUSY, EACCES...)
        // must propagate — treating it as an empty list would let a later
        // writeCsv() silently wipe every row.
        if (err.code === 'ENOENT') return callback(null, []);
        return callback(err, null);
      }
      let lines = data.trim().split('\n');
      let rows = [];
      for (let i = 1; i < lines.length; i++) {
        let row = parseCsvLine(lines[i]);
        if (row) rows.push(row);
      }
      callback(null, rows);
    });
  }

  function writeCsv(rows, callback) {
    callback = callback || function() {};
    let lines = [CSV_HEADER];
    for (let i = 0; i < rows.length; i++) lines.push(rowToCsv(rows[i]));

    // Atomic write: temp file + rename, so a crash mid-write can never
    // leave a half-written certificates.csv
    let tmp = csvPath() + '.tmp';
    fs.writeFile(tmp, lines.join('\n') + '\n', function(err) {
      if (err) return callback(err);
      fs.rename(tmp, csvPath(), callback);
    });
  }

  // --- CSV write serialization ---
  // Several async paths mutate certificates.csv: renewal results, ARI
  // refreshes (one per domain, in parallel), expiry back-fills, add/remove.
  // Each mutation is a read-modify-write of the WHOLE file, so two running
  // concurrently silently lose one update. A FIFO lock makes every mutation
  // atomic relative to the others.
  let csv_queue = [];
  let csv_busy = false;

  function withCsvLock(task) {
    csv_queue.push(task);
    drainCsvQueue();
  }

  function drainCsvQueue() {
    if (csv_busy || csv_queue.length === 0) return;
    csv_busy = true;
    let task = csv_queue.shift();
    let released = false;
    task(function release() {
      if (released) return;
      released = true;
      csv_busy = false;
      drainCsvQueue();
    });
  }

  function updateCsvRow(domain, updates, callback) {
    withCsvLock(function(release) {
      readCsv(function(err, rows) {
        if (err) {
          // Refuse to write over data we could not read
          release();
          if (callback) callback(err);
          return;
        }
        let found = false;
        for (let i = 0; i < rows.length; i++) {
          if (rows[i].domain === domain) {
            for (let k in updates) rows[i][k] = updates[k];
            found = true;
            break;
          }
        }
        if (!found) {
          // e.g. renewNow() on a domain whose CSV row went missing —
          // append instead of silently dropping the update
          let row = { domain: domain, status: 'pending', issued_at: '', expires_at: '',
                      renew_after: '', last_attempt: '', last_error: '' };
          for (let k in updates) row[k] = updates[k];
          rows.push(row);
        }
        writeCsv(rows, function(werr) {
          release();
          if (callback) callback(werr);
        });
      });
    });
  }


  // --- Account ---

  function loadAccount(callback) {
    fs.readFile(accountPath(), 'utf8', function(err, data) {
      if (err) return callback(null, null);
      try { callback(null, JSON.parse(data)); } catch(e) {
        console.error('[cert-manager] account.json is corrupt (' + e.message + ') — a NEW ACME account will be registered');
        callback(null, null);
      }
    });
  }

  // 0600: account.json may hold the account's private key, and each
  // certificate's JSON its key. Readable by the process owner only.
  function writePrivate(file, data, callback) {
    callback = callback || function() {};
    fs.writeFile(file, data, { mode: 0o600 }, function(err) {
      if (err) return callback(err);
      // mode applies only when the file is created; an existing one from an
      // older version keeps its permissions unless they are set here
      fs.chmod(file, 0o600, function() { callback(null); });
    });
  }

  function saveAccount(account, callback) {
    writePrivate(accountPath(), JSON.stringify(account, null, 2), callback);
  }

  // The account to order with:
  //   no configured accountKey  → account.json's key and URL, as before
  //   a configured accountKey   → that key; account.json's URL only when it
  //                               was registered with this same key (same
  //                               JWK thumbprint). A file from another key
  //                               is set aside as account.json.<time>.bak -
  //                               it may hold the old private key - and a
  //                               new account is registered.
  function resolveAccount(account, callback) {
    if (!account_key) {
      if (account && account.key) return callback({ key: account.key, url: account.url || null });
      return callback({ key: null, url: null });
    }

    if (!account) return callback({ key: config.accountKey, url: null });

    let saved_thumbprint = null;
    try {
      if (account.jwk) saved_thumbprint = loadKey({ publicKey: account.jwk, sign: function() {} }, { use: 'account' }).thumbprint;
      else if (account.key) saved_thumbprint = loadKey(account.key, { use: 'account' }).thumbprint;
    } catch (e) { saved_thumbprint = null; }

    if (saved_thumbprint === account_key.thumbprint) {
      return callback({ key: config.accountKey, url: account.url || null });
    }

    let backup = accountPath() + '.' + Date.now() + '.bak';
    fs.rename(accountPath(), backup, function(err) {
      emitError('account', new Error('account.json belongs to a different key than accountKey - ' +
        (err ? 'could not set it aside (' + err.message + ')' : 'moved to ' + path.basename(backup)) +
        '; registering a new ACME account'));
      callback({ key: config.accountKey, url: null });
    });
  }


  // --- Cert JSON ---

  function loadCert(domain, callback) {
    fs.readFile(certPath(domain), 'utf8', function(err, data) {
      if (err) return callback(null, null);
      try { callback(null, JSON.parse(data)); } catch(e) { callback(null, null); }
    });
  }

  function saveCert(domain, data, callback) {
    writePrivate(certPath(domain), JSON.stringify(data, null, 2), callback);
  }


  // --- Init directory ---

  function ensureDir(callback) {
    fs.mkdir(config.dir, { recursive: true }, function() {
      fs.access(csvPath(), function(err) {
        if (err) writeCsv([], callback);
        else if (callback) callback();
      });
    });
  }


  /**
   * When to renew, derived from the certificate's ACTUAL lifetime.
   * Margin before expiry = min(renewBeforeDays, lifetime/3):
   *   - 90-day cert:  min(7d, 30d)    = 7d      → renew at day 83 (unchanged behavior)
   *   - 160h cert:    min(7d, ~53.3h) = ~53.3h  → renew after ~4.4 days
   * Without the lifetime/3 cap, renewBeforeDays (7d) would be LONGER than a
   * short-lived cert's entire life, putting renew_after in the past at
   * issuance time — a permanent renew-retry loop.
   */
  function computeRenewAfter(issued, expires) {
    let lifetime = expires.getTime() - issued.getTime();
    if (lifetime <= 0) return new Date(issued.getTime());
    let margin = Math.min(config.renewBeforeDays * 86400000, lifetime / 3);
    return new Date(expires.getTime() - margin);
  }


  // --- ARI (ACME Renewal Information, RFC 9773) ---
  //
  // Instead of relying only on the local renew_after computation, ask the CA
  // when IT recommends renewing. This gives us: emergency early-renewal
  // signals before mass revocations, load-spread renewal times, and (with
  // the `replaces` field on the renewal order) exemption from rate limits.
  //
  // The endpoint is unauthenticated: GET {renewalInfo}/{certId}. We poll it
  // per-domain no more often than the CA's Retry-After (default 6h), store
  // the state in the domain JSON, and write the chosen renewal time into the
  // CSV's renew_after — so the normal scan logic stays the single source of
  // truth for WHEN to renew.

  let ari_url = null;
  let ari_url_loading = false;
  let ari_inflight = {};

  function getAriEndpoint(callback) {
    if (!config.ari || est || !provider_info) return callback(null);     // ARI is ACME's
    if (ari_url) return callback(ari_url);
    if (ari_url_loading) return callback(null);   // another lookup is running — skip this round
    ari_url_loading = true;

    let http = new AcmeHttp(provider_info.directory);
    http.getDirectory(function(err) {
      ari_url_loading = false;
      if (err) return callback(null);
      ari_url = http.getUrl('renewalInfo') || null;   // null → CA doesn't offer ARI
      callback(ari_url);
    });
  }

  // RFC 9773 §4.3: pick a UNIFORM RANDOM moment inside the suggested window
  // (spreads client load); if that moment is already in the past, renew now.
  function pickTimeInWindow(start, end, now) {
    let s = start.getTime(), e = end.getTime();
    if (e <= s) return new Date(Math.max(s, now.getTime()));
    let t = s + Math.random() * (e - s);
    return new Date(Math.max(t, now.getTime()));
  }

  function refreshAriForDomain(domain) {
    if (!config.ari || stopped || ari_inflight[domain]) return;
    ari_inflight[domain] = true;

    loadCert(domain, function(err, data) {
      if (!data || !data.cert) { delete ari_inflight[domain]; return; }

      let now = Date.now();
      if (data.ari && data.ari.nextCheck && now < new Date(data.ari.nextCheck).getTime()) {
        delete ari_inflight[domain]; return;
      }

      let cert_id = getAriCertId(data.cert);
      if (!cert_id) { delete ari_inflight[domain]; return; }   // no AKI → ARI n/a

      getAriEndpoint(function(endpoint) {
        if (!endpoint) { delete ari_inflight[domain]; return; }

        httpRequest(endpoint + '/' + cert_id, 'GET', {}, null, function(err2, res) {
          let next_check = new Date(now + 6 * 3600000);   // default 6h; 1h on errors

          if (err2 || !res || res.status !== 200 || !res.json || !res.json.suggestedWindow) {
            next_check = new Date(now + 3600000);
            data.ari = { nextCheck: next_check.toISOString(), lastError: err2 ? err2.message : ('HTTP ' + (res ? res.status : '?')) };
            saveCert(domain, data, function() { delete ari_inflight[domain]; });
            return;
          }

          if (res.headers['retry-after']) {
            let ra = parseInt(res.headers['retry-after'], 10);
            if (!isNaN(ra) && ra > 0) next_check = new Date(now + ra * 1000);
          }

          let w = res.json.suggestedWindow;
          let renew_at = pickTimeInWindow(new Date(w.start), new Date(w.end), new Date(now));

          data.ari = {
            nextCheck: next_check.toISOString(),
            windowStart: w.start,
            windowEnd: w.end,
            renewAt: renew_at.toISOString(),
            explanationURL: res.json.explanationURL || null,
          };

          if (stopped) { delete ari_inflight[domain]; return; }
          saveCert(domain, data, function() {
            // The CA's word becomes the row's renew_after — the scan logic
            // needs no ARI awareness at all
            updateCsvRow(domain, { renew_after: renew_at.toISOString() }, function() {
              delete ari_inflight[domain];
            });
          });
        }, { timeout: 15000 });
      });
    });
  }


  // --- External certificates ---
  //
  // A certificate issued somewhere else — another server that owns the
  // renewal, or a file the operator installed — kept here so it is served,
  // listed and delivered like any other, but never renewed from here. Its row
  // carries status 'external'; the scan skips it, ARI is not polled for it,
  // and renewNow() refuses it. The source replaces it by storing a newer one.

  // Everything that can be wrong with a certificate handed to store(), found
  // before anything is written. Parsing it here rather than trusting the
  // caller is what keeps a mistaken push — the wrong file, the key from the
  // previous certificate, a certificate for another name — from replacing a
  // working certificate with one that fails every handshake.
  function checkExternalCert(domain, pem) {
    if (!pem || !pem.cert || !pem.key) return { error: new Error('cert and key are required') };

    let cert, key;
    try { cert = readCert(pem.cert); }
    catch (e) { return { error: new Error('cert is not a PEM certificate: ' + e.message) }; }
    try { key = keys.privateKey(pem.key); }
    catch (e) { return { error: new Error('key is not a PEM private key: ' + e.message) }; }
    if (pem.ca && !Array.isArray(pem.ca)) {
      try { certificatePems(pem.ca); }
      catch (e) { return { error: new Error('ca is not a PEM bundle: ' + e.message) }; }
    }

    let certKey = cert.publicKey();
    if (!certKey || spkiHex(key) !== spkiHex(certKey)) {
      return { error: new Error('key does not belong to this certificate') };
    }

    // The name in the subjectAltName (cryptographic-formats, RFC 9525): an address
    // against its iPAddress names, a host against its DNS names, a wildcard
    // a whole leftmost label. Not the common name — browsers stopped
    // reading it in 2017, so a certificate with nothing else covers no one.
    let covers;
    try { covers = x509.hostname_matches(cert.cf, domain); } catch (e) { covers = false; }
    if (!covers) return { error: new Error('certificate does not cover ' + domain) };

    let issued = new Date(cert.notBefore.getTime());
    let expires = new Date(cert.notAfter.getTime());
    if (expires.getTime() <= Date.now()) {
      return { error: new Error('certificate expired at ' + expires.toISOString()) };
    }
    return { issued: issued, expires: expires };
  }

  // The chain as the rest of the manager keeps it: an array of PEM blocks,
  // the shape an issued certificate's `ca` has. Accepts that, or one string
  // holding several blocks, as a PEM bundle file does.
  function normCa(ca) {
    if (!ca) return [];
    if (Array.isArray(ca)) return ca;
    return certificatePems(ca);      // checked in checkExternalCert
  }

  // Nobody renews an external certificate here, so the one failure that
  // matters is the source going quiet. Once a certificate is past the point
  // where a managed one would have been renewed and nothing newer has
  // arrived, say so — at most hourly, since the scan runs every few minutes.
  let external_warned = {};

  function warnIfExternalDue(row, now) {
    if (!row.issued_at || !row.expires_at) return;
    let due = computeRenewAfter(new Date(row.issued_at), new Date(row.expires_at));
    if (now.getTime() < due.getTime()) return;
    if (now.getTime() - (external_warned[row.domain] || 0) < 3600000) return;
    external_warned[row.domain] = now.getTime();
    let hoursLeft = Math.round((new Date(row.expires_at).getTime() - now.getTime()) / 3600000);
    emitError(row.domain, new Error('external certificate is due for replacement and nothing newer has been stored — ' +
      (hoursLeft > 0 ? hoursLeft + 'h left' : 'EXPIRED')));
  }


  // --- Timer ---

  function scheduleCheck(delay) {
    if (stopped) return;
    if (check_timer) { clearTimeout(check_timer); check_timer = null; }
    check_timer = setTimeout(checkAll, delay);
  }


  // --- Process single domain ---

  function processDomain(domain) {
    if (stopped) { current = null; return; }
    loadCert(domain, function(err, domainConfig) {
      domainConfig = domainConfig || {};

      // The scan never picks an external row; this is renewNow() asking.
      // Issuing here would start a second owner for the name — two servers
      // renewing independently, each overwriting the other.
      if (domainConfig.external) {
        current = null;
        emitError(domain, new Error('certificate is external — it is renewed where it was issued, not here'));
        return;
      }

      // EST has no account: straight to the certificate's key
      let withAccount = est
        ? function(cb) { cb(null, {}); }
        : function(cb) { loadAccount(function(err2, saved) { resolveAccount(saved, function(account) { cb(null, account); }); }); };

      withAccount(function(err2, account) {
        resolveCertKey(domain, function(kerr, cert_key) {
          if (stopped) { current = null; return; }
          if (kerr) {
            updateCsvRow(domain, { status: 'error', last_error: ('certKey: ' + (kerr.message || kerr)).substring(0, 100), last_attempt: new Date().toISOString() }, function() {
              emitError(domain, kerr);
              current = null;
              scheduleCheck(100);
            });
            return;
          }
          startOrder(domain, domainConfig, account, cert_key);
        });
      });
    });
  }


  // certKey(domain, cb) when configured; null otherwise (a fresh key per
  // certificate, as always). Called once per issuance.
  function resolveCertKey(domain, callback) {
    if (!config.certKey) return callback(null, null);
    let answered = false;
    function once(err, key) {
      if (answered) return;
      answered = true;
      if (err) return callback(err);
      if (key == null) return callback(null, null);
      try { loadKey(key, { use: 'certificate' }); } catch (e) { return callback(e); }
      callback(null, key);
    }
    try { config.certKey(domain, once); } catch (e) { once(e); }
  }


  function startOrder(domain, domainConfig, account, cert_key) {
        let orderOpts = est ? {
          domain: domain,
          wildcard: !!domainConfig.wildcard,
          email: domainConfig.email || config.email,
          provider: config.provider,
          auth: config.auth,
        } : {
          domain: domain,
          wildcard: !!domainConfig.wildcard,
          email: domainConfig.email || config.email,
          provider: config.provider,
          staging: config.staging,
          eab: config.eab,
          preflight: true,
          autoVerify: true,
        };

        // EST renews with the current certificate (simplereenroll), when its
        // key is here; refused, the order falls back to auth
        if (est && domainConfig.cert && domainConfig.key) {
          orderOpts.renew = { cert: domainConfig.cert, key: domainConfig.key };
        }

        // Per-domain challenge/profile settings (required for IP identifiers:
        // dns-01 is forbidden for them, so the caller must have chosen
        // http-01 or tls-alpn-01 in add())
        if (!est && domainConfig.challengeType) orderOpts.challengeType = domainConfig.challengeType;
        if (!est && domainConfig.profile) orderOpts.profile = domainConfig.profile;

        // autoVerify: false — for setups where the machine cannot reach its
        // own public IP (NAT without hairpinning). External reachability
        // should then be established by the caller (e.g. port-mapper)
        // before done() is called.
        if (!est && domainConfig.autoVerify === false) orderOpts.autoVerify = false;

        // ARI `replaces` (RFC 9773 §5): tell the CA which certificate this
        // renewal replaces — inside the suggested window this exempts the
        // renewal from rate limits. Order retries once without it if the CA
        // rejects (e.g. cert already replaced), so it can never block renewal.
        if (!est && config.ari && domainConfig.cert) {
          let prev_id = getAriCertId(domainConfig.cert);
          if (prev_id) orderOpts.replaces = prev_id;
        }

        if (!est && account.key) {
          orderOpts.accountKey = account.key;
          // Known account URL — Order skips the newAccount round-trip entirely
          if (account.url) orderOpts.accountUrl = account.url;
        }
        if (cert_key) orderOpts.privateKey = cert_key;
        if (config.signTimeout) orderOpts.signTimeout = config.signTimeout;
        if (config.signRetries >= 0) orderOpts.signRetries = config.signRetries;

        readCsv(function(err3, rows) {
          if (err3 || !rows) rows = [];
          let daysLeft = null;
          for (let i = 0; i < rows.length; i++) {
            if (rows[i].domain === domain && rows[i].expires_at) {
              daysLeft = Math.floor((new Date(rows[i].expires_at).getTime() - Date.now()) / 86400000);
              break;
            }
          }

          ev.emit('renewing', domain, daysLeft);

          updateCsvRow(domain, { last_attempt: new Date().toISOString() }, function() {

            // stop() may have been called during the async chain above —
            // never create an orphan order after shutdown
            if (stopped) { current = null; return; }

            let finished = false;

            function finish() {
              if (finished) return;
              finished = true;
              if (current_timeout) { clearTimeout(current_timeout); current_timeout = null; }
              current = null;
              current_order = null;
              // After stop(), never reschedule — this orphaned path used to
              // silently resurrect the manager
              if (!stopped) scheduleCheck(100);
            }

            current_order = new Order(orderOpts);

            current_timeout = setTimeout(function() {
              if (current_order) current_order.abort();
              updateCsvRow(domain, { status: 'error', last_error: 'timeout' });
              emitError(domain, new Error('Renewal timed out after ' + Math.round(config.orderTimeout / 1000) + 's'));
              finish();
            }, config.orderTimeout);

            current_order.on('account', function(acct) {
              // A key that is not ours to keep (configured, or a signer)
              // leaves only its public half on disk.
              if (account_key) saveAccount({ url: acct.url, jwk: account_key.jwk });
              else saveAccount({ key: acct.key, url: acct.url });
            });

            current_order.on('dns', function(records, done) {
              ev.emit('dns', domain, records, done);
            });

            current_order.on('http', function(records, done) {
              ev.emit('http', domain, records, done);
            });

            current_order.on('tls-alpn', function(records, done) {
              ev.emit('tls-alpn', domain, records, done);
            });

            // The CA is still deciding - an approval, a slow signer (EST 202, ACME 'processing')
            current_order.on('pending', function(info) {
              ev.emit('pending', domain, info);
            });

            current_order.on('certificate', function(cert) {
              let now = new Date();
              let expires = cert.expiresAt ? new Date(cert.expiresAt) : new Date(now.getTime() + 90 * 86400000);
              let renewAfter = computeRenewAfter(now, expires);

              saveCert(domain, {
                domain: domain, wildcard: orderOpts.wildcard, email: orderOpts.email,
                challengeType: domainConfig.challengeType || null,
                profile: domainConfig.profile || null,
                cert: cert.cert, ca: cert.ca, key: cert.key, csr: cert.csr,
              }, function() {
                updateCsvRow(domain, {
                  status: 'active',
                  // Full ISO timestamps — day granularity is useless for
                  // 160-hour certificates whose renewal window is measured
                  // in hours. Old date-only rows still parse via new Date().
                  issued_at: now.toISOString(),
                  expires_at: expires.toISOString(),
                  renew_after: renewAfter.toISOString(),
                  last_error: '',
                }, function() {
                  ev.emit('certificate', domain, cert);
                  finish();
                });
              });
            });

            current_order.on('error', function(err, step) {
              updateCsvRow(domain, { status: 'error', last_error: (err.message || '').substring(0, 100) }, function() {
                emitError(domain, err);
                finish();
              });
            });

            current_order.start();
          });
        });
  }


  // --- Check all domains ---

  function checkAll() {
    // Called by its own timer, and directly by add() / start(). A direct
    // call must cancel the pending timer, not only forget it: a forgotten
    // timer cannot be cleared by stop(), and kept the process alive for up
    // to checkInterval after shutdown.
    if (check_timer) clearTimeout(check_timer);
    check_timer = null;
    if (stopped) return;

    // The 'scanning' flag is taken synchronously BEFORE the async read.
    // Without it, add() calling checkAll() while a scheduled scan is mid-read
    // let two scans pass the `current` guard and start two parallel orders.
    if (current !== null || scanning) { scheduleCheck(config.checkInterval); return; }
    scanning = true;

    fs.readFile(csvPath(), 'utf8', function(err, data) {
      if (err || !data) { scanning = false; scheduleCheck(config.checkInterval); return; }

      let now = new Date();
      let candidates = [];
      let lines = data.trim().split('\n');
      let pending_fills = 0;
      let scan_done = false;

      function onScanComplete() {
        if (candidates.length === 0) { scanning = false; scheduleCheck(config.checkInterval); return; }

        candidates.sort(function(a, b) {
          if (!a.last_attempt && !b.last_attempt) return 0;
          if (!a.last_attempt) return -1;
          if (!b.last_attempt) return 1;
          return new Date(a.last_attempt).getTime() - new Date(b.last_attempt).getTime();
        });

        current = candidates[0].domain;
        scanning = false;
        processDomain(candidates[0].domain);
      }

      for (let i = 1; i < lines.length; i++) {
        let row = parseCsvLine(lines[i]);
        if (!row) continue;

        // Renewed by its source, not here — only watched.
        if (row.status === 'external') {
          warnIfExternalDue(row, now);
          continue;
        }

        if (!row.issued_at || row.status === 'pending') {
          // Never issued. The first attempt goes at once — but a failed one
          // is still a failure, and waits like any other.
          //
          // Without this check a domain that had never been issued bypassed
          // the retry interval entirely, and since a finished attempt
          // schedules the next scan 100ms later, a failing one (a rejected
          // contact address, a port the CA cannot reach) was retried several
          // times a second, indefinitely. Against production that exhausts
          // Let's Encrypt's per-IP account and failed-validation limits within
          // minutes, and locks the machine out for hours — for a problem that
          // needed fixing, not retrying. renewNow() still forces an attempt.
          if (row.status === 'error' && row.last_attempt &&
              now.getTime() - new Date(row.last_attempt).getTime() < config.retryInterval) {
            continue;
          }
          candidates.push({ domain: row.domain, last_attempt: row.last_attempt });
          continue;
        }

        // Missing expires_at — fill from cert
        if (!row.expires_at && row.status === 'active') {
          pending_fills++;
          (function(r) {
            loadCert(r.domain, function(err2, certData) {
              if (certData && certData.cert) {
                let dates = getCertDates(certData.cert);
                if (dates) {
                  r.renew_after = computeRenewAfter(dates.issued, dates.expires).toISOString();
                  updateCsvRow(r.domain, {
                    expires_at: dates.expires.toISOString(),
                    renew_after: r.renew_after,
                  });
                }
              }
              if (!r.renew_after || now.getTime() >= new Date(r.renew_after).getTime()) {
                candidates.push({ domain: r.domain, last_attempt: r.last_attempt });
              }
              pending_fills--;
              if (pending_fills === 0 && scan_done) onScanComplete();
            });
          })(row);
          continue;
        }

        // Keep the CA's opinion fresh (no-op if checked recently / disabled).
        // Fire-and-forget: updates land in the JSON+CSV for the NEXT scan.
        if (row.status === 'active') refreshAriForDomain(row.domain);

        // Date-object comparison — works for both new full-ISO values and
        // legacy date-only (YYYY-MM-DD) rows, which parse as UTC midnight
        if (row.renew_after && now.getTime() < new Date(row.renew_after).getTime()) continue;

        if (row.last_attempt) {
          let retry = config.retryInterval;
          // A 4-hour retry gap is fine for 90-day certs but eats a huge
          // slice of a short-lived cert's safety margin. Within 48h of
          // expiry, retry every 30 minutes instead.
          if (row.expires_at) {
            let left = new Date(row.expires_at).getTime() - now.getTime();
            if (left > 0 && left < 48 * 3600000) {
              retry = Math.min(retry, 30 * 60000);
            }
          }
          if (now.getTime() - new Date(row.last_attempt).getTime() < retry) continue;
        }

        candidates.push({ domain: row.domain, last_attempt: row.last_attempt });
      }

      scan_done = true;
      if (pending_fills === 0) onScanComplete();
    });
  }


  // ==================== Public API ====================

  let api = {
    on: function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    add: function(domain, opts) {
      domain = normDomain(domain);
      ensureDir(function() {
        opts = opts || {};
        withCsvLock(function(release) {
          readCsv(function(err, rows) {
            if (err) { release(); emitError(domain, err); return; }
            for (let i = 0; i < rows.length; i++) {
              if (rows[i].domain === domain) { release(); return; }
            }
            // Merge with any existing cert JSON — never clobber a stored
            // certificate just because the CSV row went missing
            loadCert(domain, function(e2, existing) {
              let data = existing || {};
              data.domain = domain;
              data.wildcard = !!opts.wildcard;
              data.email = opts.email || config.email;
              if (opts.challengeType) data.challengeType = opts.challengeType;
              if (opts.profile) data.profile = opts.profile;
              if (opts.autoVerify === false) data.autoVerify = false;

              saveCert(domain, data, function() {
                rows.push({
                  domain: domain, status: 'pending', issued_at: '', expires_at: '',
                  renew_after: '', last_attempt: '', last_error: '',
                });
                writeCsv(rows, function() {
                  release();
                  checkAll();
                });
              });
            });
          });
        });
      });
    },

    remove: function(domain) {
      domain = normDomain(domain);
      // If this domain is being processed right now, abort it first
      if (current === domain) {
        if (current_order) { current_order.abort(); current_order = null; }
        if (current_timeout) { clearTimeout(current_timeout); current_timeout = null; }
        current = null;
      }
      withCsvLock(function(release) {
        readCsv(function(err, rows) {
          if (err || !rows) { release(); return; }
          let filtered = [];
          for (let i = 0; i < rows.length; i++) {
            if (rows[i].domain !== domain) filtered.push(rows[i]);
          }
          writeCsv(filtered, function() {
            release();
            fs.unlink(certPath(domain), function() {});
          });
        });
      });
    },

    get: function(domain, callback) {
      domain = normDomain(domain);
      loadCert(domain, function(err, data) {
        if (!data) return callback(null, null);

        if (data.cert) {
          let dates = getCertDates(data.cert);
          if (dates) {
            data.issued_at = dates.issued;
            data.expires_at = dates.expires;
          }
          data.status = data.external ? 'external' : 'active';
        } else {
          data.status = 'pending';
        }

        callback(null, data);
      });
    },
    list: function(callback) { readCsv(callback); },

    /**
     * Keep a certificate issued somewhere else.
     *
     *   mgr.store('example.com', { cert, key, ca }, function(err, result) { ... })
     *
     * Checked before anything is written: the key must belong to the
     * certificate, the certificate must cover the name, and it must not have
     * expired. A certificate older than the one already stored is ignored, so
     * pushes arriving out of order cannot roll it back.
     *
     * Stored as external: served and delivered exactly like an issued one —
     * 'certificate' fires, with { external: true } as a third argument — but
     * never renewed here. The source keeps it current by storing newer ones.
     * A domain this manager was issuing for becomes external too; storing is
     * the caller saying who owns the name from now on.
     *
     * result: { stored: true, expiresAt } or { stored: false, reason }
     */
    store: function(domain, pem, callback) {
      callback = callback || function() {};
      domain = normDomain(domain);

      let check = checkExternalCert(domain, pem);
      if (check.error) { setImmediate(callback, check.error); return; }

      ensureDir(function() {
        // An issuance in flight for this name is superseded
        if (current === domain) {
          if (current_order) { current_order.abort(); current_order = null; }
          if (current_timeout) { clearTimeout(current_timeout); current_timeout = null; }
          current = null;
        }

        loadCert(domain, function(e, existing) {
          if (existing && existing.cert) {
            if (existing.cert === pem.cert && existing.external) {
              return callback(null, { stored: false, reason: 'unchanged' });
            }
            let prev = getCertDates(existing.cert);
            if (prev && prev.expires.getTime() > check.expires.getTime()) {
              return callback(null, { stored: false, reason: 'older than the stored certificate' });
            }
          }

          let ca = normCa(pem.ca);
          saveCert(domain, {
            domain: domain, external: true,
            cert: pem.cert, key: pem.key, ca: ca,
          }, function(serr) {
            if (serr) return callback(serr);
            updateCsvRow(domain, {
              status: 'external',
              issued_at: check.issued.toISOString(),
              expires_at: check.expires.toISOString(),
              renew_after: '', last_attempt: '', last_error: '',
            }, function(werr) {
              if (werr) return callback(werr);
              delete external_warned[domain];
              ev.emit('certificate', domain,
                { cert: pem.cert, key: pem.key, ca: ca, expiresAt: check.expires },
                { external: true });
              callback(null, { stored: true, expiresAt: check.expires });
            });
          });
        });
      });
    },

    renewNow: function(domain) {
      domain = normDomain(domain);
      if (stopped) return false;
      if (current !== null) return false;
      current = domain;
      processDomain(domain);
      return true;
    },

    status: function() { return current; },

    // Internal — exposed for tests only
    _computeRenewAfter: computeRenewAfter,
    _certPath: certPath,
    _updateCsvRow: updateCsvRow,

    start: function() {
      stopped = false;
      ensureDir(function() {
        if (check_timer === null) checkAll();
      });
    },

    stop: function() {
      stopped = true;
      if (check_timer) { clearTimeout(check_timer); check_timer = null; }
      if (current_timeout) { clearTimeout(current_timeout); current_timeout = null; }
      if (current_order) { current_order.abort(); current_order = null; }
      current = null;
      scanning = false;
    },
  };

  for (let k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }
  return this;
}

export default Manager;
