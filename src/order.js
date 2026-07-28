
import { EventEmitter } from 'node:events';
import * as nodeCrypto from 'node:crypto';
import * as net from 'node:net';
import { AcmeHttp } from './http.js';
import { generateKey, getJwk, getJwkThumbprint, createCsr, signJws, signEab, base64url, pemEncode, toAsciiDomain, ipToArpa, canonicalIp, createAlpnCertificate, getCertDates } from './crypto.js';
import { verifyDnsChallenge, verifyHttpChallenge, checkCaa } from './verify.js';
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
    accountUrl: options.accountUrl || null,  // known account URL — skips newAccount round-trip
    privateKey: options.privateKey || null,
    csr: options.csr || null,

    // Challenge type: 'dns-01' (default) | 'http-01' | 'tls-alpn-01'.
    // dns-01 is forbidden for IP identifiers (RFC 8738) — validated in start().
    challengeType: options.challengeType || 'dns-01',

    // ACME certificate profile (draft-ietf-acme-profiles), e.g. 'shortlived'.
    // Auto-set to 'shortlived' for IP orders on Let's Encrypt (policy requirement).
    profile: options.profile || null,

    // ARI (RFC 9773 §5): certificate id (from getAriCertId) of the cert this
    // order replaces. Renewals inside the ARI window with a valid `replaces`
    // are exempt from Let's Encrypt rate limits.
    replaces: options.replaces || null,
    _replaces_retried: false,

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
    autoVerifyRetries: options.autoVerifyRetries || 60,     // 60 × 5s = 5 min for DNS propagation
    validatingInterval: options.validatingInterval || 3000,
    validatingRetries: options.validatingRetries || 40,     // 40 × 3s = 2 min for CA validation
    autoStart: !!options.autoStart,

    preflight_done: false,
    preflight_result: null,

    accountKey_generated: false,
    privateKey_generated: false,
    csr_generated: false,

    account_url: options.accountUrl || null,
    account_created: !!options.accountUrl,

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

    validating_attempt: 0,

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
    _profile_checked: false,

    _completing_in_progress: false,
    _finalizing_in_progress: false,
    _directory_loading: false,
    _account_creating: false,
    _order_creating: false,
    _auths_fetching: false,
    _preflight_running: false,
    _cert_fetching: false,

    // polling loop guards — one round in flight at a time, next round is
    // scheduled only after the previous one fully completed (no pile-up)
    _verify_running: false,
    _validating_running: false,
    _ready_running: false,
    _processing_running: false,
  };


  // --- Error handling ---
  // On any error: stop all timers, release in-progress flags, move to 'error'
  // state so getState() reflects reality, and emit safely (a bare EventEmitter
  // 'error' with no listener crashes the whole process).

  function clearAllTimers() {
    let timers = ['verify_timer', 'validating_timer', 'ready_timer', 'processing_timer'];
    for (let i = 0; i < timers.length; i++) {
      if (context[timers[i]]) {
        clearTimeout(context[timers[i]]);
        context[timers[i]] = null;
      }
    }
  }

  function clearProgressFlags() {
    context._completing_in_progress = false;
    context._finalizing_in_progress = false;
    context._directory_loading = false;
    context._account_creating = false;
    context._order_creating = false;
    context._auths_fetching = false;
    context._preflight_running = false;
    context._cert_fetching = false;
    context._verify_running = false;
    context._validating_running = false;
    context._ready_running = false;
    context._processing_running = false;
  }

  function emitError(err, step) {
    clearAllTimers();
    clearProgressFlags();
    if (context.aborted === false && context.state !== 'error') {
      let old_state = context.state;
      context.state = 'error';
      ev.emit('state', 'error', old_state);
    }
    if (ev.listenerCount('error') > 0) {
      ev.emit('error', err, step);
    } else {
      // Never crash the host process because the consumer forgot a listener
      console.error('[cert-manager] unhandled order error at step "' + step + '":', err && err.message ? err.message : err);
    }
  }


  // { type: 'dns' | 'ip', value } — RFC 8555 §9.7.7 + RFC 8738 §3
  function toIdentifier(value) {
    if (net.isIP(value)) {
      return { type: 'ip', value: value };
    }
    return { type: 'dns', value: toAsciiDomain(value) };
  }

  function buildIdentifiers() {
    let ids = [];
    if (context.domain) {
      ids.push(toIdentifier(context.domain));
    }
    if (context.wildcard && context.domain) {
      // wildcard is rejected for IPs in start() before we ever get here
      ids.push({ type: 'dns', value: '*.' + toAsciiDomain(context.domain) });
    }
    if (context.altNames) {
      for (let i = 0; i < context.altNames.length; i++) {
        let id = toIdentifier(context.altNames[i]);
        let found = false;
        for (let j = 0; j < ids.length; j++) {
          if (ids[j].value === id.value) { found = true; break; }
        }
        if (!found) ids.push(id);
      }
    }
    return ids;
  }

  function hasIpIdentifier() {
    if (context.domain && net.isIP(context.domain)) return true;
    if (context.altNames) {
      for (let i = 0; i < context.altNames.length; i++) {
        if (net.isIP(context.altNames[i])) return true;
      }
    }
    return false;
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

        // CAA is a DNS record — it does not exist for IP addresses.
        // Querying resolveCaa('81.2.3.4') would just climb a meaningless
        // tree ('3.2.81' → '2.81' → ...) and waste DNS round-trips.
        //
        // CRITICAL: this same-pass transition MUST go through params_to_set.
        // A synchronous nested set_context() here re-enters the state pass
        // BEFORE this pass's params (freshly generated account/private keys!)
        // are applied — the nested pass generates a SECOND key pair, computes
        // the JWK thumbprint from it, and then pass 1's keys overwrite it.
        // Result: key authorizations signed-for by one key, thumbprinted by
        // another — every challenge rejected by the CA with a digest mismatch.
        if (net.isIP(context.domain)) {
          params_to_set['preflight_done'] = true;
          params_to_set['preflight_result'] = { caa: { skipped: 'ip-identifier' } };
        } else {
          context._preflight_running = true;

        let provider_info = PROVIDERS[context.provider] || PROVIDERS.letsencrypt;
        let caa_domain = provider_info.caa || null;

        checkCaa(context.domain, caa_domain, { wildcard: context.wildcard }, function(err, caa) {
          if (context.aborted) return;
          if (err) { emitError(err, 'preflight'); return; }

          if (caa.exists === true && caa.allowed === false) {
            emitError(new Error('CAA record does not allow ' + caa_domain + ' to issue certificates for ' + context.domain), 'preflight');
            return;
          }

          set_context({ preflight_done: true, preflight_result: { caa: caa } });
        });
        }
      }

      // preflight done -> load directory
      if (context.state === 'preflight' && context.preflight_done === true && context.directory_loaded === false && context._directory_loading === false) {
        context._directory_loading = true;
        context.http.getDirectory(function(err) {
          if (context.aborted) return;
          if (err) { emitError(err, 'account'); return; }
          set_context({ directory_loaded: true, state: 'account' });
        });
      }


      // --- STATE: account ---

      if (context.state === 'account' && context.directory_loaded === false && context._directory_loading === false) {
        context._directory_loading = true;
        context.http.getDirectory(function(err) {
          if (context.aborted) return;
          if (err) { emitError(err, 'account'); return; }
          set_context({ directory_loaded: true });
        });
      }

      // --- Validate requested profile against the CA's advertised profiles ---
      // draft-ietf-acme-profiles: clients SHOULD NOT request a profile that
      // isn't advertised in directory meta. Failing here turns an opaque
      // server rejection into an immediate, self-explanatory local error.
      // If the CA doesn't advertise profiles at all, we send anyway —
      // servers ignore unknown newOrder fields.

      if (context.directory_loaded === true && context.profile !== null && context._profile_checked === false) {
        context._profile_checked = true;

        let dir_data = context.http.getDirectoryData();
        let offered = dir_data && dir_data.meta && dir_data.meta.profiles;

        if (offered && !(context.profile in offered)) {
          emitError(new Error("Profile '" + context.profile + "' is not offered by this CA. Available profiles: " + Object.keys(offered).join(', ')), 'order');
        }
      }


      // Account already known (accountUrl provided) — skip newAccount entirely
      if (context.state === 'account' && context.directory_loaded === true && context.account_created === true && context.account_url !== null) {
        params_to_set['state'] = 'order';
      }

      if (context.state === 'account' && context.directory_loaded === true && context.account_created === false && context.accountKey !== null && context._account_creating === false) {
        context._account_creating = true;

        let new_account_url = context.http.getUrl('newAccount');
        if (!new_account_url) {
          emitError(new Error("ACME directory has no 'newAccount' URL — not a valid ACME v2 directory?"), 'account');
        } else {

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
            if (err) { emitError(err, 'account'); return; }

            if (res.status === 200 || res.status === 201) {
              let acct_url = res.headers['location'] || null;

              ev.emit('account', { url: acct_url, key: context.accountKey });

              set_context({
                account_url: acct_url,
                account_created: true,
                state: 'order',
              });
            } else {
              emitError(new Error('Account creation failed: HTTP ' + res.status + ' ' + JSON.stringify(res.json)), 'account');
            }
          });
        }
      }


      // --- STATE: order ---

      if (context.state === 'order' && context.order_created === false && context.account_created === true && context.accountKey !== null && context._order_creating === false) {
        context._order_creating = true;

        let new_order_url = context.http.getUrl('newOrder');
        if (!new_order_url) {
          emitError(new Error("ACME directory has no 'newOrder' URL — not a valid ACME v2 directory?"), 'order');
        } else {

          let order_payload = { identifiers: context.identifiers };
          if (context.profile) {
            order_payload.profile = context.profile;
          }
          if (context.replaces) {
            order_payload.replaces = context.replaces;
          }

          context.http.signedRequest(new_order_url, order_payload, context.accountKey, context.account_url, function(err, res) {
            if (context.aborted) return;
            if (err) { emitError(err, 'order'); return; }

            if (res.status === 201) {
              let order_status = res.json ? res.json.status : null;

              let next = {
                order_url: res.headers['location'] || null,
                order_data: res.json,
                order_created: true,
                finalize_url: res.json.finalize || null,
              };

              if (order_status === 'ready') {
                // Authorization reuse (common on renewals with an existing account):
                // the CA already validated us — no DNS records needed, go straight to finalize.
                next.authorizations_fetched = true;
                next.authorizations = [];
                next.challenges = [];
                next.challenges_ready = true;
                next.challenges_emitted = true;
                next.challenges_done = true;
                next.all_verified = true;
                next.challenges_submitted = true;
                next.all_authorizations_valid = true;
                next.order_ready = true;
                next.state = 'finalizing';
              } else if (order_status === 'valid' && res.json.certificate) {
                // Order already has a certificate — just download it.
                next.authorizations_fetched = true;
                next.authorizations = [];
                next.challenges = [];
                next.challenges_ready = true;
                next.challenges_emitted = true;
                next.challenges_done = true;
                next.all_verified = true;
                next.challenges_submitted = true;
                next.all_authorizations_valid = true;
                next.order_ready = true;
                next.order_finalized = true;
                next.certificate_url = res.json.certificate;
                next.state = 'certificate';
              } else {
                next.state = 'challenges';
              }

              set_context(next);
            } else if (context.replaces !== null && context._replaces_retried === false) {
              // A rejected `replaces` (e.g. the old cert was already replaced,
              // or belongs to another environment) must not block renewal.
              // Retry ONCE without it — losing the rate-limit exemption is
              // better than losing the certificate.
              context._replaces_retried = true;
              context.replaces = null;
              context._order_creating = false;
              set_context({ order_data: null });   // re-trigger the state pass
            } else {
              emitError(new Error('Order creation failed: HTTP ' + res.status + ' ' + JSON.stringify(res.json)), 'order');
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
          // same-pass transition → params_to_set (see preflight comment)
          context._auths_fetching = false;
          params_to_set['authorizations_fetched'] = true;
          params_to_set['authorizations'] = [];
        } else {

          let auth_errors = [];

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
                } else {
                  auth_errors.push(auth_url + ': ' + (err ? err.message : 'HTTP ' + (res ? res.status : '?')));
                }

                auth_left--;
                if (auth_left <= 0) {
                  if (auth_errors.length === 0) {
                    set_context({ authorizations: auth_results, authorizations_fetched: true });
                  } else {
                    // A PARTIAL fetch must fail loudly. Proceeding with a
                    // subset would submit fewer challenges than the order
                    // requires — and then poll a forever-pending order.
                    emitError(new Error('Failed to fetch ' + auth_errors.length + '/' + auth_urls.length + ' authorizations: ' + auth_errors.join('; ')), 'challenge');
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
        let had_authorizations = context.authorizations.length > 0;
        let missing_type = [];

        for (let a = 0; a < context.authorizations.length; a++) {
          let auth = context.authorizations[a];
          // Skip authorizations the CA already validated (authorization reuse) —
          // responding to their challenges again would be rejected.
          if (auth.status === 'valid') continue;
          if (!auth.challenges) continue;

          // Pick the challenge matching the configured type
          let ch = null;
          for (let b = 0; b < auth.challenges.length; b++) {
            if (auth.challenges[b].type === context.challengeType) { ch = auth.challenges[b]; break; }
          }

          if (!ch) {
            // The CA decides which challenge types each identifier may use.
            // Fail with the full picture instead of a silent skip.
            let offered_types = [];
            for (let b = 0; b < auth.challenges.length; b++) offered_types.push(auth.challenges[b].type);
            missing_type.push(auth.identifier.value + ' (offered: ' + offered_types.join(', ') + ')');
            continue;
          }

          let key_authorization = ch.token + '.' + context.jwk_thumbprint;

          let challenge_info = {
            type: ch.type,
            url: ch.url,
            token: ch.token,
            key_authorization: key_authorization,
            identifier: auth.identifier,
            auth_url: auth.url,
          };

          if (ch.type === 'dns-01') {
            let hash = nodeCrypto.createHash('sha256').update(key_authorization).digest();
            challenge_info.domain = '_acme-challenge.' + auth.identifier.value.replace('*.', '');
            challenge_info.value = base64url(hash);
          } else if (ch.type === 'http-01') {
            // The CA fetches http://<identifier>/.well-known/acme-challenge/<token>
            // on port 80 and expects the raw key authorization as the body.
            // For IP identifiers the Host header will be the IP itself (RFC 8738 §5).
            challenge_info.path = '/.well-known/acme-challenge/' + ch.token;
          } else if (ch.type === 'tls-alpn-01') {
            // RFC 8737: the validation cert carries the SHA-256 digest of the
            // key authorization (as OCTET STRING, inside the critical
            // acmeIdentifier extension) — never the key authorization text.
            let digest = nodeCrypto.createHash('sha256').update(key_authorization).digest();
            challenge_info.key_authorization_digest = new Uint8Array(digest);
            // SNI the CA will send: the identifier itself for domains;
            // the in-addr.arpa / ip6.arpa reverse name for IPs (RFC 8738 §6)
            challenge_info.sni_name = net.isIP(auth.identifier.value)
              ? ipToArpa(auth.identifier.value)
              : auth.identifier.value;
          }

          all_challenges.push(challenge_info);
        }

        if (missing_type.length > 0) {
          emitError(new Error("CA offered no '" + context.challengeType + "' challenge for: " + missing_type.join('; ')), 'challenge');
        } else {

        params_to_set['challenges'] = all_challenges;
        params_to_set['challenges_ready'] = true;

        if (had_authorizations && all_challenges.length === 0) {
          // Every authorization was already valid — nothing to prove.
          // Skip dns/verify/completing entirely and poll the order until 'ready'.
          params_to_set['challenges_emitted'] = true;
          params_to_set['challenges_done'] = true;
          params_to_set['all_verified'] = true;
          params_to_set['challenges_submitted'] = true;
          params_to_set['all_authorizations_valid'] = true;
          params_to_set['state'] = 'ready';
        }
        }
      }


      // --- Emit challenge event (dns / http / tls-alpn) ---

      if (context.challenges_ready === true && context.challenges_emitted === false && context.challenges !== null) {

        let records = [];
        let event_name = 'dns';

        if (context.challengeType === 'http-01') {
          event_name = 'http';
          // The consumer must serve keyAuthorization as the plain-text body at
          // http://<identifier>:80<path> — then call done().
          for (let i = 0; i < context.challenges.length; i++) {
            records.push({
              type: 'http-01',
              identifier: context.challenges[i].identifier.value,
              token: context.challenges[i].token,
              keyAuthorization: context.challenges[i].key_authorization,
              path: context.challenges[i].path,
              required: true,
            });
          }
        } else if (context.challengeType === 'tls-alpn-01') {
          event_name = 'tls-alpn';
          // The consumer (e.g. a TLS layer like lemon-tls) must present
          // record.cert/record.key on port 443 when the incoming SNI equals
          // sniName (the CA offers ALPN 'acme-tls/1' — include it in the
          // server's ALPN list so negotiation succeeds). Then call done().
          // The certificate is pre-built per RFC 8737/8738: single-entry SAN
          // (iPAddress bytes for IPs) + critical acmeIdentifier extension.
          for (let i = 0; i < context.challenges.length; i++) {
            let alpn_cert = createAlpnCertificate(
              context.challenges[i].identifier.value,
              context.challenges[i].key_authorization
            );
            records.push({
              type: 'tls-alpn-01',
              identifier: context.challenges[i].identifier.value,
              token: context.challenges[i].token,
              keyAuthorization: context.challenges[i].key_authorization,
              keyAuthorizationDigest: context.challenges[i].key_authorization_digest,
              sniName: context.challenges[i].sni_name,
              alpnProtocol: 'acme-tls/1',
              cert: alpn_cert.cert,
              key: alpn_cert.key,
              required: true,
            });
          }
        } else {
          // dns-01 — unchanged behavior, including optional CAA suggestions
          for (let i = 0; i < context.challenges.length; i++) {
            records.push({
              type: 'TXT',
              name: context.challenges[i].domain,
              value: context.challenges[i].value,
              required: true,
            });
          }

          let provider_info = PROVIDERS[context.provider] || PROVIDERS.letsencrypt;
          let caa_domain = provider_info.caa || null;

          // CAA records are OPTIONAL: per RFC 8659, absence of CAA means any CA
          // may issue. These are only a recommendation to restrict issuance —
          // automation should NOT create them blindly (check record.required).
          if (caa_domain) {
            let suggest_caa = true;
            if (context.preflight_result && context.preflight_result.caa) {
              if (context.preflight_result.caa.exists === true && context.preflight_result.caa.allowed === true) {
                suggest_caa = false;
              }
            }

            if (suggest_caa) {
              records.push({
                type: 'CAA',
                name: context.domain,
                value: '0 issue "' + caa_domain + '"',
                required: false,
              });

              if (context.wildcard) {
                records.push({
                  type: 'CAA',
                  name: context.domain,
                  value: '0 issuewild "' + caa_domain + '"',
                  required: false,
                });
              }
            }
          }
        }

        let done_called = false;

        function done(opts) {
          if (done_called) return;
          done_called = true;

          opts = opts || {};
          let skip_verify = opts.skipVerify || false;

          // tls-alpn-01 has no cheap local self-check (it would require a raw
          // TLS handshake with custom ALPN against ourselves) — go straight
          // to completing and let the CA validate.
          if (skip_verify || context.autoVerify === false || context.challengeType === 'tls-alpn-01') {
            set_context({ challenges_done: true, all_verified: true, state: 'completing' });
          } else {
            set_context({ challenges_done: true, state: 'verifying' });
          }
        }

        // retry applies to the SELF-VERIFICATION stage only (before anything
        // was submitted to the CA). Once the CA has marked a challenge
        // invalid, the whole order is dead — a fresh order is the only fix.
        done.retry = function() {
          context.verify_attempt = 0;
          context.all_verified = false;
          set_context({ state: 'verifying' });
        };

        params_to_set['challenges_emitted'] = true;

        setTimeout(function() {
          ev.emit(event_name, records, done);
        }, 0);
      }


      // --- STATE: verifying (autoVerify polling) ---

      if (context.state === 'verifying' && context.challenges_done === true && context.all_verified === false && context._verify_running === false) {

        if (context.challenges.length === 0) {
          // same-pass transition → params_to_set (see preflight comment)
          params_to_set['all_verified'] = true;
          params_to_set['state'] = 'completing';
        } else {

        context._verify_running = true;

        let verifyRound = function() {
          if (context.aborted || context.state !== 'verifying') {
            context._verify_running = false;
            return;
          }

          let total = context.challenges.length;
          let ok_count = 0;
          let checked = 0;
          let results = [];

          for (let i = 0; i < context.challenges.length; i++) {
            (function(ch) {
              let checkOne = function(cb) {
                if (ch.type === 'http-01') {
                  return verifyHttpChallenge(ch.identifier.value, ch.token, ch.key_authorization, cb);
                }
                return verifyDnsChallenge(ch.domain, ch.value, cb);
              };

              checkOne(function(err, found) {
                if (context.aborted) { context._verify_running = false; return; }

                if (found === true) ok_count++;
                results.push({ domain: ch.domain || ch.identifier.value, found: !!found });
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
                    context._verify_running = false;
                    set_context({ all_verified: true, state: 'completing' });
                  } else if (context.verify_attempt >= context.autoVerifyRetries) {
                    context._verify_running = false;
                    emitError(new Error("Challenge verification ('" + context.challengeType + "') failed after " + context.autoVerifyRetries + ' attempts (fix the records/server, then call done.retry())'), 'verify');
                  } else {
                    // Schedule next round only after this one fully completed
                    context.verify_timer = setTimeout(verifyRound, context.autoVerifyInterval);
                  }
                }
              });
            })(context.challenges[i]);
          }
        };

        verifyRound();
        }
      }


      // --- STATE: completing — POST {} to each challenge URL ---

      if (context.state === 'completing' && context.all_verified === true && context.challenges_submitted === false && context._completing_in_progress === false) {
        context._completing_in_progress = true;

        // No deduplication — each challenge has a unique URL from the CA
        let selected = context.challenges;

        if (selected.length === 0) {
          // same-pass transition → params_to_set (see preflight comment)
          params_to_set['challenges_submitted'] = true;
          params_to_set['state'] = 'validating';
        } else {
          let submit_left = selected.length;
          let submit_results = [];
          let submit_errors = [];

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
                if (err) submit_errors.push(ch.identifier.value + ': ' + err.message);

                submit_left--;
                if (submit_left <= 0) {
                  ev.emit('completing', { results: submit_results });

                  if (submit_errors.length > 0) {
                    // Emit ONE error after the whole batch — emitting mid-loop
                    // would wedge the state machine while requests are in flight
                    emitError(new Error('Failed to submit ' + submit_errors.length + '/' + selected.length + ' challenges: ' + submit_errors.join('; ')), 'challenge');
                  } else {
                    set_context({ challenges_submitted: true, state: 'validating' });
                  }
                }
              });
            })(selected[i]);
          }
        }
      }


      // --- STATE: validating — poll challenge URLs until all valid ---

      if (context.state === 'validating' && context.challenges_submitted === true && context.all_authorizations_valid === false && context._validating_running === false) {

        context._validating_running = true;
        context.validating_attempt = 0;

        // All challenge URLs — each is unique
        let challenge_urls = [];
        for (let i = 0; i < context.challenges.length; i++) {
          challenge_urls.push({ url: context.challenges[i].url, identifier: context.challenges[i].identifier.value });
        }

        if (challenge_urls.length === 0) {
          // Nothing to validate (all authorizations were already valid).
          // Same-pass transition → params_to_set (see preflight comment)
          context._validating_running = false;
          params_to_set['all_authorizations_valid'] = true;
          params_to_set['state'] = 'ready';
        } else {

          let validateRound = function() {
            if (context.aborted || context.state !== 'validating') {
              context._validating_running = false;
              return;
            }

            let total = challenge_urls.length;
            let valid_count = 0;
            let checked = 0;
            let invalid = false;
            let statuses = [];

            for (let i = 0; i < challenge_urls.length; i++) {
              (function(ch_info) {
                // POST-as-GET to challenge URL (same as acme-client waitForValidStatus)
                context.http.signedRequest(ch_info.url, '', context.accountKey, context.account_url, function(err, res) {
                  if (context.aborted) { context._validating_running = false; return; }

                  let status = (err ? 'error' : (res.json ? res.json.status : 'unknown'));
                  statuses.push(ch_info.identifier + ':' + status);

                  if (status === 'valid') valid_count++;
                  if (status === 'invalid' && invalid === false) {
                    invalid = true;
                    context._validating_running = false;
                    emitError(new Error('Challenge invalid: ' + JSON.stringify(res.json)), 'challenge');
                  }
                  checked++;

                  if (checked >= total && invalid === false) {
                    context.validating_attempt++;
                    ev.emit('validating', { attempt: context.validating_attempt, statuses: statuses });

                    if (valid_count >= total) {
                      context._validating_running = false;
                      set_context({ all_authorizations_valid: true, state: 'ready' });
                    } else if (context.validating_attempt >= context.validatingRetries) {
                      context._validating_running = false;
                      emitError(new Error('CA validation timed out. Statuses: ' + statuses.join(', ')), 'challenge');
                    } else {
                      context.validating_timer = setTimeout(validateRound, context.validatingInterval);
                    }
                  }
                });
              })(challenge_urls[i]);
            }
          };

          validateRound();
        }
      }


      // --- STATE: ready — poll order until status "ready" ---

      if (context.state === 'ready' && context.all_authorizations_valid === true && context.order_ready === false && context._ready_running === false) {

        context._ready_running = true;

        let readyRound = function() {
          if (context.aborted || context.state !== 'ready') {
            context._ready_running = false;
            return;
          }

          context.http.signedRequest(context.order_url, '', context.accountKey, context.account_url, function(err, res) {
            if (context.aborted) { context._ready_running = false; return; }

            let status = (err ? 'error' : (res.json ? res.json.status : 'unknown'));

            if (status === 'valid' && res.json.certificate) {
              // Order is already valid — finalizing it again would fail
              // (orderNotReady). Jump straight to certificate download.
              context._ready_running = false;
              set_context({
                order_ready: true,
                order_finalized: true,
                certificate_url: res.json.certificate,
                state: 'certificate',
              });
            } else if (status === 'ready') {
              context._ready_running = false;
              set_context({ order_ready: true, state: 'finalizing' });
            } else if (status === 'invalid') {
              context._ready_running = false;
              emitError(new Error('Order invalid: ' + JSON.stringify(res.json)), 'finalize');
            } else {
              context.ready_timer = setTimeout(readyRound, retryAfterDelay(res, 2000));
            }
          });
        };

        readyRound();
      }


      // --- STATE: finalizing — POST CSR ---

      if (context.state === 'finalizing' && context.order_ready === true && context.finalize_url !== null && context.csr !== null && context.order_finalized === false && context._finalizing_in_progress === false) {
        context._finalizing_in_progress = true;

        context.http.signedRequest(context.finalize_url, { csr: base64url(context.csr) }, context.accountKey, context.account_url, function(err, res) {
          if (context.aborted) return;
          if (err) { emitError(err, 'finalize'); return; }

          if (res.status === 200 || res.status === 201) {
            let cert_url = (res.json && res.json.certificate) || null;

            if (res.json && res.json.status === 'valid' && cert_url) {
              set_context({ order_finalized: true, certificate_url: cert_url, state: 'certificate' });
            } else {
              set_context({ order_finalized: true, state: 'processing' });
            }
          } else {
            emitError(new Error('Finalize failed: HTTP ' + res.status + ' ' + JSON.stringify(res.json)), 'finalize');
          }
        });
      }


      // --- STATE: processing — poll order until "valid" + certificate URL ---

      if (context.state === 'processing' && context.order_finalized === true && context.certificate_url === null && context._processing_running === false) {

        context._processing_running = true;

        let processingRound = function() {
          if (context.aborted || context.state !== 'processing') {
            context._processing_running = false;
            return;
          }

          context.http.signedRequest(context.order_url, '', context.accountKey, context.account_url, function(err, res) {
            if (context.aborted) { context._processing_running = false; return; }

            if (!err && res.json && res.json.status === 'valid' && res.json.certificate) {
              context._processing_running = false;
              set_context({ certificate_url: res.json.certificate, state: 'certificate' });
            } else if (!err && res.json && res.json.status === 'invalid') {
              context._processing_running = false;
              emitError(new Error('Order invalid: ' + JSON.stringify(res.json)), 'certificate');
            } else {
              // Transient error or still processing — keep polling
              context.processing_timer = setTimeout(processingRound, retryAfterDelay(err ? null : res, 2000));
            }
          });
        };

        processingRound();
      }


      // --- STATE: certificate — download cert ---

      if (context.state === 'certificate' && context.certificate_url !== null && context.cert_fetched === false && context._cert_fetching === false) {
        context._cert_fetching = true;

        context.http.signedRequest(context.certificate_url, '', context.accountKey, context.account_url, function(err, res) {
          if (context.aborted) return;
          if (err) { emitError(err, 'certificate'); return; }

          if (res.status === 200) {
            let cert_pem = res.body.toString('utf8');

            // Split PEM chain: first = server cert, rest = CA chain
            let pems = splitPemChain(cert_pem);

            let cert_obj = {
              cert: pems[0] || cert_pem,
              ca: pems.length > 1 ? pems.slice(1) : [],
              key: context.privateKey,
              csr: pemEncode(context.csr, 'CERTIFICATE REQUEST'),
              expiresAt: extractExpiry(pems[0] || cert_pem),
            };

            set_context({ cert: cert_obj, cert_fetched: true });
            ev.emit('certificate', cert_obj);
          } else {
            emitError(new Error('Certificate download failed: HTTP ' + res.status), 'certificate');
          }
        });
      }


      // --- recursive set_context ---
      if (Object.keys(params_to_set).length > 0) {
        set_context(params_to_set);
      }

    }
  }


  /**
   * Compute polling delay from a Retry-After header (RFC 8555 recommends
   * clients respect it). Falls back to default_ms; capped at 2 minutes.
   */
  function retryAfterDelay(res, default_ms) {
    if (res && res.headers && res.headers['retry-after']) {
      let ra = parseInt(res.headers['retry-after'], 10);
      if (!isNaN(ra) && ra > 0) {
        return Math.min(ra * 1000, 120000);
      }
    }
    return default_ms;
  }


  function splitPemChain(pem) {
    let certs = [];
    let parts = pem.split('-----BEGIN CERTIFICATE-----');
    for (let i = 1; i < parts.length; i++) {
      certs.push('-----BEGIN CERTIFICATE-----' + parts[i].split('-----END CERTIFICATE-----')[0] + '-----END CERTIFICATE-----\n');
    }
    return certs;
  }


  function extractExpiry(cert_pem) {
    let dates = getCertDates(cert_pem);
    return dates ? dates.expires : null;
  }


  let api = {

    context: context,

    on: function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    set_context: set_context,

    start: function() {
      if (context.aborted) return;

      // Normalize IP inputs to RFC 5952 canonical form ONCE, up front.
      // RFC 8738 requires the canonical textual form in ACME identifiers,
      // and canonical strings make dedup ('2a02::1' vs '2a02:0:...:0:1')
      // and every downstream comparison trivially correct.
      if (context.domain && net.isIP(context.domain)) {
        context.domain = canonicalIp(context.domain);
      }
      if (context.altNames && context.altNames.length > 0) {
        let normalized = [];
        for (let i = 0; i < context.altNames.length; i++) {
          let n = context.altNames[i];
          normalized.push(net.isIP(n) ? canonicalIp(n) : n);
        }
        context.altNames = normalized;
      }

      // Validate upfront — a missing email would otherwise surface as a
      // cryptic 'mailto:null' rejection from the CA, deep into the flow.
      let problems = [];
      if (!context.domain) problems.push('domain is required');
      if (!context.email) problems.push('email is required');
      if (context.provider === 'zerossl' && !(context.eab && context.eab.kid && context.eab.hmacKey)) {
        problems.push('ZeroSSL requires eab: { kid, hmacKey }');
      }
      if (options.accountUrl && !options.accountKey) {
        problems.push('accountUrl requires accountKey (the key that registered that account)');
      }
      let provider_info = PROVIDERS[context.provider];
      if (!provider_info) {
        problems.push('unknown provider: ' + context.provider);
      } else if (context.staging && !provider_info.staging) {
        problems.push("provider '" + context.provider + "' has no staging environment");
      }

      // --- Challenge type / IP identifier rules ---
      let known_types = ['dns-01', 'http-01', 'tls-alpn-01'];
      if (known_types.indexOf(context.challengeType) < 0) {
        problems.push("unknown challengeType: '" + context.challengeType + "' (supported: " + known_types.join(', ') + ')');
      }

      let has_ip = hasIpIdentifier();

      if (has_ip && context.wildcard) {
        problems.push('wildcard is not applicable to IP addresses');
      }
      if (context.wildcard && context.challengeType !== 'dns-01') {
        problems.push('wildcard certificates require dns-01 (CA policy)');
      }
      if (has_ip && context.challengeType === 'dns-01') {
        // Fail here, locally and clearly — not with an opaque CA rejection.
        problems.push("dns-01 must not be used for IP identifiers (RFC 8738 §7); set challengeType: 'http-01' or 'tls-alpn-01'");
      }

      // Let's Encrypt policy: IP certificates must use the 'shortlived'
      // profile. There is no real choice here, so fill it in automatically
      // rather than fail — but never silently override an explicit choice.
      if (has_ip && context.provider === 'letsencrypt') {
        if (context.profile === null) {
          context.profile = 'shortlived';
        } else if (context.profile !== 'shortlived') {
          problems.push("Let's Encrypt requires profile: 'shortlived' for IP certificates (got '" + context.profile + "')");
        }
      }

      if (problems.length > 0) {
        // Async so listeners attached right after start() still catch it
        process.nextTick(function() {
          emitError(new Error('Invalid options: ' + problems.join('; ')), 'options');
        });
        return;
      }

      if (context.preflight) {
        set_context({ state: 'preflight' });
      } else {
        set_context({ state: 'account' });
      }
    },

    abort: function() {
      let step = context.state;
      clearAllTimers();
      clearProgressFlags();
      set_context({ aborted: true, state: 'aborted' });
      ev.emit('abort', step);
    },

    getState: function() { return context.state; },
    getDomain: function() { return context.domain; },
    getProfile: function() { return context.profile; },
    getChallengeType: function() { return context.challengeType; },
    getAccountKey: function() { return context.accountKey; },
    getPrivateKey: function() { return context.privateKey; },
    getCsr: function() { return context.csr; },                    // DER (Uint8Array) — or whatever was provided
    getCsrPem: function() {
      return context.csr ? pemEncode(context.csr, 'CERTIFICATE REQUEST') : null;
    },
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
