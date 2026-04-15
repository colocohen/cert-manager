
import { EventEmitter } from 'node:events';
import * as nodeCrypto from 'node:crypto';
import { AcmeHttp } from './http.js';
import { generateKey, getJwk, getJwkThumbprint, createCsr, signJws, signEab, base64url } from './crypto.js';
import { verifyDnsChallenge, checkCaa } from './verify.js';
import { PROVIDERS } from './providers.js';


function Order(options) {
  if (!(this instanceof Order)) return new Order(options);
  options = options || {};

  const ev = new EventEmitter();

  let context = {

    state: 'new',

    domain: options.domain || null,
    email: options.email || null,
    wildcard: !!options.wildcard,
    altNames: options.altNames || [],
    provider: options.provider || 'letsencrypt',
    staging: !!options.staging,

    accountKey: options.accountKey || null,
    privateKey: options.privateKey || null,
    csr: options.csr || null,

    // EAB (External Account Binding) for ZeroSSL etc.
    eab: options.eab || null,  // { kid: '...', hmacKey: '...' }

    // CSR extra fields
    csrFields: options.csrFields || {},  // { country, state, locality, organization, organizationUnit }

    keyType: options.keyType || 'ecdsa',
    keyCurve: options.keyCurve || 'P-256',
    keySize: options.keySize || 2048,

    preflight: options.preflight !== false,
    autoVerify: options.autoVerify !== false,
    autoVerifyInterval: options.autoVerifyInterval || 5000,
    autoVerifyRetries: options.autoVerifyRetries || 10,
    autoStart: !!options.autoStart,

    preflight_done: false,
    preflight_result: null,

    accountKey_generated: false,
    privateKey_generated: false,
    csr_generated: false,

    account_url: null,
    account_created: false,

    order_url: null,
    order_data: null,
    order_created: false,

    identifiers: [],

    authorizations: null,
    authorizations_fetched: false,

    challenges: null,
    challenges_ready: false,
    challenges_done: false,
    challenges_emitted: false,

    verify_attempt: 0,
    verify_timer: null,
    all_verified: false,

    challenges_completed: false,
    all_valid: false,
    valid_count: 0,
    valid_total: 0,

    // reactive state flags
    challenges_submitted: false,
    all_authorizations_valid: false,
    order_ready: false,

    // polling timers
    validating_timer: null,
    ready_timer: null,
    processing_timer: null,

    finalize_url: null,
    order_finalized: false,

    certificate_url: null,
    cert: null,
    cert_fetched: false,

    jwk: null,
    jwk_thumbprint: null,

    aborted: false,

    http: null,
    directory_loaded: false,

    _completing_in_progress: false,
    _finalizing_in_progress: false,
    _directory_loading: false,
    _account_creating: false,
    _order_creating: false,
    _auths_fetching: false,
    _preflight_running: false,
    _cert_fetching: false,
  };


  function buildIdentifiers() {
    let ids = [];
    if (context.domain) {
      ids.push({ type: 'dns', value: context.domain });
    }
    if (context.wildcard && context.domain) {
      ids.push({ type: 'dns', value: '*.' + context.domain });
    }
    if (context.altNames) {
      for (let i = 0; i < context.altNames.length; i++) {
        let found = false;
        for (let j = 0; j < ids.length; j++) {
          if (ids[j].value === context.altNames[i]) { found = true; break; }
        }
        if (!found) ids.push({ type: 'dns', value: context.altNames[i] });
      }
    }
    return ids;
  }


  function set_context(opts) {
    let has_changed = false;

    if (opts && typeof opts === 'object') {

      let fields = [
        'state', 'accountKey', 'privateKey', 'csr',
        'accountKey_generated', 'privateKey_generated', 'csr_generated',
        'preflight_done', 'directory_loaded',
        'account_url', 'account_created',
        'order_url', 'order_created',
        'authorizations_fetched',
        'challenges_ready', 'challenges_done', 'challenges_emitted',
        'all_verified',
        'challenges_submitted', 'all_authorizations_valid', 'order_ready',
        'finalize_url', 'order_finalized',
        'certificate_url', 'cert_fetched',
        'jwk_thumbprint', 'aborted',
      ];

      for (let f = 0; f < fields.length; f++) {
        let key = fields[f];
        if (key in opts) {
          if (opts[key] !== context[key]) {
            if (key === 'state') {
              ev.emit('state', opts[key], context[key]); // new_state, old_state
            }
            context[key] = opts[key];
            has_changed = true;
          }
        }
      }

      // object fields (no equality check)
      let obj_fields = ['preflight_result', 'order_data', 'authorizations', 'challenges', 'cert', 'jwk'];
      for (let f = 0; f < obj_fields.length; f++) {
        let key = obj_fields[f];
        if (key in opts) {
          context[key] = opts[key];
          has_changed = true;
        }
      }
    }


    if (has_changed === true) {

      let params_to_set = {};

      if (context.aborted === true) {
        return;
      }


      // --- generate keys if missing ---

      if (context.accountKey === null && context.accountKey_generated === false) {
        let key = (context.keyType === 'rsa')
          ? generateKey('rsa', { size: context.keySize })
          : generateKey('ecdsa', { curve: context.keyCurve });
        params_to_set['accountKey'] = key;
        params_to_set['accountKey_generated'] = true;
      }

      if (context.privateKey === null && context.privateKey_generated === false) {
        let key = (context.keyType === 'rsa')
          ? generateKey('rsa', { size: context.keySize })
          : generateKey('ecdsa', { curve: context.keyCurve });
        params_to_set['privateKey'] = key;
        params_to_set['privateKey_generated'] = true;
      }


      // --- generate JWK ---

      if (context.jwk === null && context.accountKey !== null) {
        let jwk = getJwk(context.accountKey);
        params_to_set['jwk'] = jwk;
        params_to_set['jwk_thumbprint'] = getJwkThumbprint(jwk);
      }


      // --- generate CSR ---

      if (context.csr === null && context.csr_generated === false && context.privateKey !== null && context.domain !== null) {
        let alt = [];
        if (context.domain) alt.push(context.domain);
        if (context.wildcard) alt.push('*.' + context.domain);
        if (context.altNames) {
          for (let i = 0; i < context.altNames.length; i++) {
            if (alt.indexOf(context.altNames[i]) < 0) alt.push(context.altNames[i]);
          }
        }

        let csr_opts = {
          commonName: context.domain,
          altNames: alt,
          emailAddress: context.email,
        };

        // Merge extra CSR fields
        let extra = context.csrFields;
        if (extra.country) csr_opts.country = extra.country;
        if (extra.state) csr_opts.state = extra.state;
        if (extra.locality) csr_opts.locality = extra.locality;
        if (extra.organization) csr_opts.organization = extra.organization;
        if (extra.organizationUnit) csr_opts.organizationUnit = extra.organizationUnit;

        let csr_der = createCsr(csr_opts, context.privateKey);

        params_to_set['csr'] = csr_der;
        params_to_set['csr_generated'] = true;
      }


      // --- build identifiers ---

      if (context.identifiers.length === 0 && context.domain !== null) {
        context.identifiers = buildIdentifiers();
      }


      // --- init HTTP client ---

      if (context.http === null && context.state !== 'new') {
        let provider = PROVIDERS[context.provider] || PROVIDERS.letsencrypt;
        let dir_url = context.staging ? provider.staging : provider.production;
        if (!dir_url) dir_url = provider.production;
        context.http = new AcmeHttp(dir_url);
      }


      // --- STATE: preflight ---

      if (context.state === 'preflight' && context.preflight_done === false && context._preflight_running === false) {
        context._preflight_running = true;
        let provider_info = PROVIDERS[context.provider] || PROVIDERS.letsencrypt;
        let caa_domain = provider_info.caa || null;

        checkCaa(context.domain, caa_domain, function(err, caa) {
          if (context.aborted) return;
          if (err) { ev.emit('error', err, 'preflight'); return; }

          if (caa.exists === true && caa.allowed === false) {
            ev.emit('error', new Error('CAA record does not allow ' + caa_domain + ' to issue certificates for ' + context.domain), 'preflight');
            return;
          }

          set_context({ preflight_done: true, preflight_result: { caa: caa } });
        });
      }

      // preflight done -> load directory
      if (context.state === 'preflight' && context.preflight_done === true && context.directory_loaded === false && context._directory_loading === false) {
        context._directory_loading = true;
        context.http.getDirectory(function(err) {
          if (context.aborted) return;
          if (err) { ev.emit('error', err, 'account'); return; }
          set_context({ directory_loaded: true, state: 'account' });
        });
      }


      // --- STATE: account ---

      if (context.state === 'account' && context.directory_loaded === false && context._directory_loading === false) {
        context._directory_loading = true;
        context.http.getDirectory(function(err) {
          if (context.aborted) return;
          if (err) { ev.emit('error', err, 'account'); return; }
          set_context({ directory_loaded: true });
        });
      }

      if (context.state === 'account' && context.directory_loaded === true && context.account_created === false && context.accountKey !== null && context._account_creating === false) {
        context._account_creating = true;

        let new_account_url = context.http.getUrl('newAccount');
        if (new_account_url) {

          let payload = {
            termsOfServiceAgreed: true,
            contact: ['mailto:' + context.email],
          };

          // EAB (External Account Binding) for ZeroSSL etc.
          if (context.eab && context.eab.kid && context.eab.hmacKey) {
            payload.externalAccountBinding = signEab(
              context.eab.kid,
              context.eab.hmacKey,
              context.jwk,
              new_account_url
            );
          }

          context.http.signedRequest(new_account_url, payload, context.accountKey, null, function(err, res) {
            if (context.aborted) return;
            if (err) { ev.emit('error', err, 'account'); return; }

            if (res.status === 200 || res.status === 201) {
              let acct_url = res.headers['location'] || null;

              ev.emit('account', { url: acct_url, key: context.accountKey });

              set_context({
                account_url: acct_url,
                account_created: true,
                state: 'order',
              });
            } else {
              ev.emit('error', new Error('Account creation failed: HTTP ' + res.status + ' ' + JSON.stringify(res.json)), 'account');
            }
          });
        }
      }


      // --- STATE: order ---

      if (context.state === 'order' && context.order_created === false && context.account_created === true && context.accountKey !== null && context._order_creating === false) {
        context._order_creating = true;

        let new_order_url = context.http.getUrl('newOrder');
        if (new_order_url) {

          context.http.signedRequest(new_order_url, { identifiers: context.identifiers }, context.accountKey, context.account_url, function(err, res) {
            if (context.aborted) return;
            if (err) { ev.emit('error', err, 'order'); return; }

            if (res.status === 201) {
              set_context({
                order_url: res.headers['location'] || null,
                order_data: res.json,
                order_created: true,
                finalize_url: res.json.finalize || null,
                state: 'challenges',
              });
            } else {
              ev.emit('error', new Error('Order creation failed: HTTP ' + res.status + ' ' + JSON.stringify(res.json)), 'order');
            }
          });
        }
      }


      // --- STATE: challenges — fetch authorizations ---

      if (context.state === 'challenges' && context.order_created === true && context.authorizations_fetched === false && context.order_data !== null && context._auths_fetching === false) {
        context._auths_fetching = true;

        let auth_urls = context.order_data.authorizations || [];
        let auth_results = [];
        let auth_left = auth_urls.length;

        if (auth_left === 0) {
          set_context({ authorizations_fetched: true, authorizations: [] });
        } else {

          for (let i = 0; i < auth_urls.length; i++) {
            (function(auth_url) {
              context.http.signedRequest(auth_url, '', context.accountKey, context.account_url, function(err, res) {
                if (context.aborted) return;

                if (!err && res.json) {
                  auth_results.push({
                    url: auth_url,
                    identifier: res.json.identifier,
                    challenges: res.json.challenges,
                    status: res.json.status,
                  });
                }

                auth_left--;
                if (auth_left <= 0) {
                  if (auth_results.length > 0) {
                    set_context({ authorizations: auth_results, authorizations_fetched: true });
                  } else {
                    ev.emit('error', err || new Error('Failed to fetch authorizations'), 'challenge');
                  }
                }
              });
            })(auth_urls[i]);
          }
        }
      }


      // --- Extract challenges and compute key authorizations ---

      if (context.authorizations_fetched === true && context.challenges_ready === false && context.authorizations !== null && context.jwk_thumbprint !== null) {

        let all_challenges = [];

        for (let a = 0; a < context.authorizations.length; a++) {
          let auth = context.authorizations[a];
          if (!auth.challenges) continue;

          for (let b = 0; b < auth.challenges.length; b++) {
            let ch = auth.challenges[b];
            let key_authorization = ch.token + '.' + context.jwk_thumbprint;

            let challenge_info = {
              type: ch.type,
              url: ch.url,
              token: ch.token,
              key_authorization: key_authorization,
              identifier: auth.identifier,
              auth_url: auth.url,
            };

            // dns-01 only
            if (ch.type === 'dns-01') {
              let hash = nodeCrypto.createHash('sha256').update(key_authorization).digest();
              challenge_info.domain = '_acme-challenge.' + auth.identifier.value.replace('*.', '');
              challenge_info.value = base64url(hash);
              all_challenges.push(challenge_info);
            }
          }
        }

        params_to_set['challenges'] = all_challenges;
        params_to_set['challenges_ready'] = true;
      }


      // --- Emit dns event ---

      if (context.challenges_ready === true && context.challenges_emitted === false && context.challenges !== null) {

        let provider_info = PROVIDERS[context.provider] || PROVIDERS.letsencrypt;
        let caa_domain = provider_info.caa || null;

        let records = [];

        for (let i = 0; i < context.challenges.length; i++) {
          records.push({
            type: 'TXT',
            name: context.challenges[i].domain,
            value: context.challenges[i].value,
          });
        }

        if (caa_domain) {
          let needs_caa = true;
          if (context.preflight_result && context.preflight_result.caa) {
            if (context.preflight_result.caa.exists === true && context.preflight_result.caa.allowed === true) {
              needs_caa = false;
            }
          }

          if (needs_caa) {
            records.push({
              type: 'CAA',
              name: context.domain,
              value: '0 issue "' + caa_domain + '"',
            });

            if (context.wildcard) {
              records.push({
                type: 'CAA',
                name: context.domain,
                value: '0 issuewild "' + caa_domain + '"',
              });
            }
          }
        }

        function done(opts) {
          opts = opts || {};
          let skip_verify = opts.skipVerify || false;

          if (skip_verify || context.autoVerify === false) {
            set_context({ challenges_done: true, all_verified: true, state: 'completing' });
          } else {
            set_context({ challenges_done: true, state: 'verifying' });
          }
        }

        done.retry = function() {
          context.verify_attempt = 0;
          context.all_verified = false;
          set_context({ state: 'verifying' });
        };

        params_to_set['challenges_emitted'] = true;

        setTimeout(function() {
          ev.emit('dns', records, done);
        }, 0);
      }


      // --- STATE: verifying (autoVerify polling) ---

      if (context.state === 'verifying' && context.challenges_done === true && context.all_verified === false) {

        if (context.verify_timer === null) {

          function doVerify() {
            if (context.aborted) return;

            let total = context.challenges.length;
            let ok_count = 0;
            let checked = 0;
            let results = [];

            for (let i = 0; i < context.challenges.length; i++) {
              (function(ch) {
                verifyDnsChallenge(ch.domain, ch.value, function(err, found) {
                  if (context.aborted) return;

                  if (found === true) ok_count++;
                  results.push({ domain: ch.domain, found: !!found });
                  checked++;

                  if (checked >= total) {
                    context.verify_attempt++;

                    ev.emit('verify', {
                      attempt: context.verify_attempt,
                      total: context.autoVerifyRetries,
                      found: ok_count,
                      expected: total,
                      results: results,
                    });

                    if (ok_count >= total) {
                      if (context.verify_timer) {
                        clearInterval(context.verify_timer);
                        context.verify_timer = null;
                      }
                      set_context({ all_verified: true, state: 'completing' });
                    } else if (context.verify_attempt >= context.autoVerifyRetries) {
                      if (context.verify_timer) {
                        clearInterval(context.verify_timer);
                        context.verify_timer = null;
                      }
                      ev.emit('error', new Error('Challenge verification failed after ' + context.autoVerifyRetries + ' attempts'), 'verify');
                    }
                  }
                });
              })(context.challenges[i]);
            }
          }

          doVerify();
          context.verify_timer = setInterval(doVerify, context.autoVerifyInterval);
        }
      }


      // --- STATE: completing — POST {} to each challenge URL ---

      if (context.state === 'completing' && context.all_verified === true && context.challenges_submitted === false && context._completing_in_progress === false) {
        context._completing_in_progress = true;

        // No deduplication — each challenge has a unique URL from the CA
        let selected = context.challenges;

        if (selected.length === 0) {
          set_context({ challenges_submitted: true, state: 'validating' });
        } else {
          let submit_left = selected.length;
          let submit_results = [];

          for (let i = 0; i < selected.length; i++) {
            (function(ch) {
              context.http.signedRequest(ch.url, {}, context.accountKey, context.account_url, function(err, res) {
                if (context.aborted) return;

                let result = {
                  identifier: ch.identifier.value,
                  url: ch.url,
                  status: err ? 'error' : (res.json ? res.json.status : 'unknown'),
                  httpStatus: err ? null : res.status,
                  error: err ? err.message : null,
                };
                submit_results.push(result);

                if (err) { ev.emit('error', err, 'challenge'); }

                submit_left--;
                if (submit_left <= 0) {
                  ev.emit('completing', { results: submit_results });
                  set_context({ challenges_submitted: true, state: 'validating' });
                }
              });
            })(selected[i]);
          }
        }
      }


      // --- STATE: validating — poll challenge URLs until all valid ---

      if (context.state === 'validating' && context.challenges_submitted === true && context.all_authorizations_valid === false) {

        if (context.validating_timer === null) {
          context.validating_attempt = 0;

          // All challenge URLs — each is unique
          let challenge_urls = [];
          for (let i = 0; i < context.challenges.length; i++) {
            challenge_urls.push({ url: context.challenges[i].url, identifier: context.challenges[i].identifier.value });
          }

          function doValidate() {
            if (context.aborted) return;

            let total = challenge_urls.length;
            let valid_count = 0;
            let checked = 0;
            let statuses = [];

            for (let i = 0; i < challenge_urls.length; i++) {
              (function(ch_info) {
                // POST-as-GET to challenge URL (same as acme-client waitForValidStatus)
                context.http.signedRequest(ch_info.url, '', context.accountKey, context.account_url, function(err, res) {
                  if (context.aborted) return;

                  let status = (err ? 'error' : (res.json ? res.json.status : 'unknown'));
                  statuses.push(ch_info.identifier + ':' + status);

                  if (status === 'valid') valid_count++;
                  if (status === 'invalid') {
                    if (context.validating_timer) { clearInterval(context.validating_timer); context.validating_timer = null; }
                    ev.emit('error', new Error('Challenge invalid: ' + JSON.stringify(res.json)), 'challenge');
                  }
                  checked++;

                  if (checked >= total) {
                    context.validating_attempt++;
                    ev.emit('validating', { attempt: context.validating_attempt, statuses: statuses });

                    if (valid_count >= total) {
                      if (context.validating_timer) { clearInterval(context.validating_timer); context.validating_timer = null; }
                      set_context({ all_authorizations_valid: true, state: 'ready' });
                    } else if (context.validating_attempt >= 30) {
                      if (context.validating_timer) { clearInterval(context.validating_timer); context.validating_timer = null; }
                      ev.emit('error', new Error('CA validation timed out. Statuses: ' + statuses.join(', ')), 'challenge');
                    }
                  }
                });
              })(challenge_urls[i]);
            }
          }

          doValidate();
          context.validating_timer = setInterval(doValidate, 3000);
        }
      }


      // --- STATE: ready — poll order until status "ready" ---

      if (context.state === 'ready' && context.all_authorizations_valid === true && context.order_ready === false) {

        if (context.ready_timer === null) {

          function doCheckReady() {
            if (context.aborted) return;

            context.http.signedRequest(context.order_url, '', context.accountKey, context.account_url, function(err, res) {
              if (context.aborted) return;

              let status = (err ? 'error' : (res.json ? res.json.status : 'unknown'));

              if (status === 'ready' || status === 'valid') {
                if (context.ready_timer) { clearInterval(context.ready_timer); context.ready_timer = null; }
                set_context({ order_ready: true, state: 'finalizing' });
              } else if (status === 'invalid') {
                if (context.ready_timer) { clearInterval(context.ready_timer); context.ready_timer = null; }
                ev.emit('error', new Error('Order invalid: ' + JSON.stringify(res.json)), 'finalize');
              }
            });
          }

          doCheckReady();
          context.ready_timer = setInterval(doCheckReady, 2000);
        }
      }


      // --- STATE: finalizing — POST CSR ---

      if (context.state === 'finalizing' && context.order_ready === true && context.finalize_url !== null && context.csr !== null && context.order_finalized === false && context._finalizing_in_progress === false) {
        context._finalizing_in_progress = true;

        context.http.signedRequest(context.finalize_url, { csr: base64url(context.csr) }, context.accountKey, context.account_url, function(err, res) {
          if (context.aborted) return;
          if (err) { ev.emit('error', err, 'finalize'); return; }

          if (res.status === 200 || res.status === 201) {
            let cert_url = (res.json && res.json.certificate) || null;

            if (res.json && res.json.status === 'valid' && cert_url) {
              set_context({ order_finalized: true, certificate_url: cert_url, state: 'certificate' });
            } else {
              set_context({ order_finalized: true, state: 'processing' });
            }
          } else {
            ev.emit('error', new Error('Finalize failed: HTTP ' + res.status + ' ' + JSON.stringify(res.json)), 'finalize');
          }
        });
      }


      // --- STATE: processing — poll order until "valid" + certificate URL ---

      if (context.state === 'processing' && context.order_finalized === true && context.certificate_url === null) {

        if (context.processing_timer === null) {

          function doCheckProcessing() {
            if (context.aborted) return;

            context.http.signedRequest(context.order_url, '', context.accountKey, context.account_url, function(err, res) {
              if (context.aborted) return;
              if (err) return;

              if (res.json && res.json.status === 'valid' && res.json.certificate) {
                if (context.processing_timer) { clearInterval(context.processing_timer); context.processing_timer = null; }
                set_context({ certificate_url: res.json.certificate, state: 'certificate' });
              } else if (res.json && res.json.status === 'invalid') {
                if (context.processing_timer) { clearInterval(context.processing_timer); context.processing_timer = null; }
                ev.emit('error', new Error('Order invalid: ' + JSON.stringify(res.json)), 'certificate');
              }
            });
          }

          doCheckProcessing();
          context.processing_timer = setInterval(doCheckProcessing, 2000);
        }
      }


      // --- STATE: certificate — download cert ---

      if (context.state === 'certificate' && context.certificate_url !== null && context.cert_fetched === false && context._cert_fetching === false) {
        context._cert_fetching = true;

        context.http.signedRequest(context.certificate_url, '', context.accountKey, context.account_url, function(err, res) {
          if (context.aborted) return;
          if (err) { ev.emit('error', err, 'certificate'); return; }

          if (res.status === 200) {
            let cert_pem = res.body.toString('utf8');

            // Split PEM chain: first = server cert, rest = CA chain
            let pems = splitPemChain(cert_pem);

            let cert_obj = {
              cert: pems[0] || cert_pem,
              ca: pems.length > 1 ? pems.slice(1) : [],
              key: context.privateKey,
              csr: pemEncodeCsr(context.csr),
              expiresAt: extractExpiry(pems[0] || cert_pem),
            };

            set_context({ cert: cert_obj, cert_fetched: true });
            ev.emit('certificate', cert_obj);
          } else {
            ev.emit('error', new Error('Certificate download failed: HTTP ' + res.status), 'certificate');
          }
        });
      }


      // --- recursive set_context ---
      if (Object.keys(params_to_set).length > 0) {
        set_context(params_to_set);
      }

    }
  }


  function splitPemChain(pem) {
    let certs = [];
    let parts = pem.split('-----BEGIN CERTIFICATE-----');
    for (let i = 1; i < parts.length; i++) {
      certs.push('-----BEGIN CERTIFICATE-----' + parts[i].split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----\n');
    }
    return certs;
  }


  function pemEncodeCsr(der) {
    if (typeof der === 'string') return der;
    let b64 = Buffer.from(der).toString('base64');
    let lines = [];
    for (let i = 0; i < b64.length; i += 64) {
      lines.push(b64.substring(i, i + 64));
    }
    return '-----BEGIN CERTIFICATE REQUEST-----\n' + lines.join('\n') + '\n-----END CERTIFICATE REQUEST-----\n';
  }


  function extractExpiry(cert_pem) {
    try {
      let x509 = new nodeCrypto.X509Certificate(cert_pem);
      return new Date(x509.validTo);
    } catch(e) {
      return null;
    }
  }


  let api = {

    context: context,

    on: function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    set_context: set_context,

    start: function() {
      if (context.aborted) return;
      if (context.preflight) {
        set_context({ state: 'preflight' });
      } else {
        set_context({ state: 'account' });
      }
    },

    abort: function() {
      let step = context.state;
      let timers = ['verify_timer', 'validating_timer', 'ready_timer', 'processing_timer'];
      for (let i = 0; i < timers.length; i++) {
        if (context[timers[i]]) {
          clearInterval(context[timers[i]]);
          context[timers[i]] = null;
        }
      }
      set_context({ aborted: true, state: 'aborted' });
      ev.emit('abort', step);
    },

    getState: function() { return context.state; },
    getDomain: function() { return context.domain; },
    getAccountKey: function() { return context.accountKey; },
    getPrivateKey: function() { return context.privateKey; },
    getCsr: function() { return context.csr; },
  };


  for (let k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) {
      this[k] = api[k];
    }
  }

  if (context.autoStart === true) {
    let self = this;
    process.nextTick(function() {
      self.start();
    });
  }

  return this;
}


export default Order;
