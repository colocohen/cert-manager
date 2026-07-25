
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as nodeCrypto from 'node:crypto';
import Order from './order.js';


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

    renewBeforeDays: options.renewBeforeDays || 7,
    checkInterval: options.checkInterval || 1000 * 60 * 10,
    retryInterval: options.retryInterval || 1000 * 60 * 60 * 4,
  };

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

  // Strip characters that would corrupt the CSV structure
  function csvSafe(value) {
    return String(value == null ? '' : value).replace(/[\r\n]+/g, ' ');
  }


  // --- File paths ---

  function csvPath() { return path.join(config.dir, 'certificates.csv'); }
  function accountPath() { return path.join(config.dir, 'account.json'); }
  function certPath(domain) { return path.join(config.dir, domain + '.json'); }


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

  function updateCsvRow(domain, updates, callback) {
    readCsv(function(err, rows) {
      if (err) {
        // Refuse to write over data we could not read
        if (callback) callback(err);
        return;
      }
      for (let i = 0; i < rows.length; i++) {
        if (rows[i].domain === domain) {
          for (let k in updates) rows[i][k] = updates[k];
          break;
        }
      }
      writeCsv(rows, callback);
    });
  }


  // --- Account ---

  function loadAccount(callback) {
    fs.readFile(accountPath(), 'utf8', function(err, data) {
      if (err) return callback(null, null);
      try { callback(null, JSON.parse(data)); } catch(e) { callback(null, null); }
    });
  }

  function saveAccount(account, callback) {
    fs.writeFile(accountPath(), JSON.stringify(account, null, 2), callback || function() {});
  }


  // --- Cert JSON ---

  function loadCert(domain, callback) {
    fs.readFile(certPath(domain), 'utf8', function(err, data) {
      if (err) return callback(null, null);
      try { callback(null, JSON.parse(data)); } catch(e) { callback(null, null); }
    });
  }

  function saveCert(domain, data, callback) {
    fs.writeFile(certPath(domain), JSON.stringify(data, null, 2), callback || function() {});
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


  // --- Expiry from cert PEM ---

  function getExpiryFromCert(cert_pem) {
    try {
      return new Date(new nodeCrypto.X509Certificate(cert_pem).validTo);
    } catch(e) { return null; }
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
      loadAccount(function(err2, account) {

        let orderOpts = {
          domain: domain,
          wildcard: !!domainConfig.wildcard,
          email: domainConfig.email || config.email,
          provider: config.provider,
          staging: config.staging,
          eab: config.eab,
          preflight: true,
          autoVerify: true,
        };

        if (account && account.key) {
          orderOpts.accountKey = account.key;
          // Known account URL — Order skips the newAccount round-trip entirely
          if (account.url) orderOpts.accountUrl = account.url;
        }

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
              emitError(domain, new Error('Renewal timed out'));
              finish();
            }, 1000 * 60 * 10);

            current_order.on('account', function(acct) {
              saveAccount({ key: acct.key, url: acct.url });
            });

            current_order.on('dns', function(records, done) {
              ev.emit('dns', domain, records, done);
            });

            current_order.on('certificate', function(cert) {
              let now = new Date();
              let expires = cert.expiresAt ? new Date(cert.expiresAt) : new Date(now.getTime() + 90 * 86400000);
              let renewAfter = new Date(expires.getTime() - config.renewBeforeDays * 86400000);

              saveCert(domain, {
                domain: domain, wildcard: orderOpts.wildcard, email: orderOpts.email,
                cert: cert.cert, ca: cert.ca, key: cert.key, csr: cert.csr,
              }, function() {
                updateCsvRow(domain, {
                  status: 'active',
                  issued_at: now.toISOString().split('T')[0],
                  expires_at: expires.toISOString().split('T')[0],
                  renew_after: renewAfter.toISOString().split('T')[0],
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
      });
    });
  }


  // --- Check all domains ---

  function checkAll() {
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
      let today = now.toISOString().split('T')[0];
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

        if (!row.issued_at || row.status === 'pending') {
          candidates.push({ domain: row.domain, last_attempt: row.last_attempt });
          continue;
        }

        // Missing expires_at — fill from cert
        if (!row.expires_at && row.status === 'active') {
          pending_fills++;
          (function(r) {
            loadCert(r.domain, function(err2, certData) {
              if (certData && certData.cert) {
                let expires = getExpiryFromCert(certData.cert);
                if (expires) {
                  r.renew_after = new Date(expires.getTime() - config.renewBeforeDays * 86400000).toISOString().split('T')[0];
                  updateCsvRow(r.domain, {
                    expires_at: expires.toISOString().split('T')[0],
                    renew_after: r.renew_after,
                  });
                }
              }
              if (!r.renew_after || today >= r.renew_after) {
                candidates.push({ domain: r.domain, last_attempt: r.last_attempt });
              }
              pending_fills--;
              if (pending_fills === 0 && scan_done) onScanComplete();
            });
          })(row);
          continue;
        }

        if (row.renew_after && today < row.renew_after) continue;

        if (row.last_attempt) {
          if (now.getTime() - new Date(row.last_attempt).getTime() < config.retryInterval) continue;
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
      ensureDir(function() {
        opts = opts || {};
        readCsv(function(err, rows) {
          if (err) { emitError(domain, err); return; }
          for (let i = 0; i < rows.length; i++) {
            if (rows[i].domain === domain) return;
          }
          // Merge with any existing cert JSON — never clobber a stored
          // certificate just because the CSV row went missing
          loadCert(domain, function(e2, existing) {
            let data = existing || {};
            data.domain = domain;
            data.wildcard = !!opts.wildcard;
            data.email = opts.email || config.email;

            saveCert(domain, data, function() {
              rows.push({
                domain: domain, status: 'pending', issued_at: '', expires_at: '',
                renew_after: '', last_attempt: '', last_error: '',
              });
              writeCsv(rows, function() { checkAll(); });
            });
          });
        });
      });
    },

    remove: function(domain) {
      // If this domain is being processed right now, abort it first
      if (current === domain) {
        if (current_order) { current_order.abort(); current_order = null; }
        if (current_timeout) { clearTimeout(current_timeout); current_timeout = null; }
        current = null;
      }
      readCsv(function(err, rows) {
        if (err || !rows) return;
        let filtered = [];
        for (let i = 0; i < rows.length; i++) {
          if (rows[i].domain !== domain) filtered.push(rows[i]);
        }
        writeCsv(filtered, function() {
          fs.unlink(certPath(domain), function() {});
        });
      });
    },

    get: function(domain, callback) {
      loadCert(domain, function(err, data) {
        if (!data) return callback(null, null);

        if (data.cert) {
          try {
            let x509 = new nodeCrypto.X509Certificate(data.cert);
            data.issued_at = new Date(x509.validFrom);
            data.expires_at = new Date(x509.validTo);
          } catch(e) {}
          data.status = 'active';
        } else {
          data.status = 'pending';
        }

        callback(null, data);
      });
    },
    list: function(callback) { readCsv(callback); },

    renewNow: function(domain) {
      if (stopped) return false;
      if (current !== null) return false;
      current = domain;
      processDomain(domain);
      return true;
    },

    status: function() { return current; },

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
