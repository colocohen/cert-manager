
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

  let CSV_HEADER = 'domain,status,issued_at,expires_at,renew_after,last_attempt,last_error';


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
    return [r.domain, r.status, r.issued_at || '', r.expires_at || '',
      r.renew_after || '', r.last_attempt || '', r.last_error || ''].join(',');
  }

  function readCsv(callback) {
    fs.readFile(csvPath(), 'utf8', function(err, data) {
      if (err) return callback(null, []);
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
    let lines = [CSV_HEADER];
    for (let i = 0; i < rows.length; i++) lines.push(rowToCsv(rows[i]));
    fs.writeFile(csvPath(), lines.join('\n') + '\n', callback || function() {});
  }

  function updateCsvRow(domain, updates, callback) {
    readCsv(function(err, rows) {
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
    if (check_timer) { clearTimeout(check_timer); check_timer = null; }
    check_timer = setTimeout(checkAll, delay);
  }


  // --- Process single domain ---

  function processDomain(domain) {
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

        if (account && account.key) orderOpts.accountKey = account.key;

        readCsv(function(err3, rows) {
          let daysLeft = null;
          for (let i = 0; i < rows.length; i++) {
            if (rows[i].domain === domain && rows[i].expires_at) {
              daysLeft = Math.floor((new Date(rows[i].expires_at).getTime() - Date.now()) / 86400000);
              break;
            }
          }

          ev.emit('renewing', domain, daysLeft);

          updateCsvRow(domain, { last_attempt: new Date().toISOString() }, function() {

            let timeout_timer = null;

            function finish() {
              if (timeout_timer) { clearTimeout(timeout_timer); timeout_timer = null; }
              current = null;
              current_order = null;
              scheduleCheck(100);
            }

            current_order = new Order(orderOpts);

            timeout_timer = setTimeout(function() {
              if (current_order) current_order.abort();
              updateCsvRow(domain, { status: 'error', last_error: 'timeout' });
              ev.emit('error', domain, new Error('Renewal timed out'));
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
              updateCsvRow(domain, { status: 'error', last_error: err.message.substring(0, 100) }, function() {
                ev.emit('error', domain, err);
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
    if (current !== null) { scheduleCheck(config.checkInterval); return; }

    fs.readFile(csvPath(), 'utf8', function(err, data) {
      if (err || !data) { scheduleCheck(config.checkInterval); return; }

      let now = new Date();
      let today = now.toISOString().split('T')[0];
      let candidates = [];
      let lines = data.trim().split('\n');
      let pending_fills = 0;
      let scan_done = false;

      function onScanComplete() {
        if (candidates.length === 0) { scheduleCheck(config.checkInterval); return; }

        candidates.sort(function(a, b) {
          if (!a.last_attempt && !b.last_attempt) return 0;
          if (!a.last_attempt) return -1;
          if (!b.last_attempt) return 1;
          return new Date(a.last_attempt).getTime() - new Date(b.last_attempt).getTime();
        });

        current = candidates[0].domain;
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
          for (let i = 0; i < rows.length; i++) {
            if (rows[i].domain === domain) return;
          }
          saveCert(domain, {
            domain: domain, wildcard: !!opts.wildcard, email: opts.email || config.email,
          }, function() {
            rows.push({
              domain: domain, status: 'pending', issued_at: '', expires_at: '',
              renew_after: '', last_attempt: '', last_error: '',
            });
            writeCsv(rows, function() { checkAll(); });
          });
        });
      });
    },

    remove: function(domain) {
      readCsv(function(err, rows) {
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
      if (current !== null) return;
      current = domain;
      processDomain(domain);
    },

    status: function() { return current; },

    start: function() {
      ensureDir(function() {
        if (check_timer === null) checkAll();
      });
    },

    stop: function() {
      if (check_timer) { clearTimeout(check_timer); check_timer = null; }
      if (current_order) { current_order.abort(); current_order = null; }
      current = null;
    },
  };

  for (let k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) this[k] = api[k];
  }
  return this;
}

export default Manager;
