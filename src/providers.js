
const PROVIDERS = {
  letsencrypt: {
    production: 'https://acme-v02.api.letsencrypt.org/directory',
    staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
    caa: 'letsencrypt.org',
  },
  zerossl: {
    production: 'https://acme.zerossl.com/v2/DV90/directory',
    staging: null,
    caa: 'sectigo.com',
  },
};

/**
 * Where certificates come from - the provider option, in any of its forms:
 *
 *   'letsencrypt' | 'zerossl'                      a known ACME CA
 *   { acme: 'https://.../directory', caa? }        any ACME server
 *   { est: 'https://est.example.com', label?, ca? } an EST server (RFC 7030)
 *
 * → { protocol: 'acme', name, directory, caa }
 *   { protocol: 'est', server, label, ca }
 *   or throws, with what is wrong.
 */
function resolveProvider(provider, staging) {
  if (provider == null) provider = 'letsencrypt';
  if (typeof provider === 'string') {
    let info = PROVIDERS[provider];
    if (!info) throw new Error('unknown provider: ' + provider + " (known: " + Object.keys(PROVIDERS).join(', ') + ", or { acme: url } / { est: url })");
    if (staging && !info.staging) throw new Error("provider '" + provider + "' has no staging environment");
    return { protocol: 'acme', name: provider, directory: staging ? info.staging : info.production, caa: info.caa || null };
  }
  if (typeof provider !== 'object') throw new Error('provider: a name, { acme: url } or { est: url }');
  if (provider.acme && provider.est) throw new Error('provider: { acme } or { est }, not both');
  if (provider.acme) {
    if (staging) throw new Error('staging applies to a named provider; for { acme: url }, give the staging URL itself');
    checkUrl(provider.acme, 'provider.acme');
    return { protocol: 'acme', name: null, directory: provider.acme, caa: provider.caa || null };
  }
  if (provider.est) {
    if (staging) throw new Error('staging applies to a named ACME provider, not to EST');
    checkUrl(provider.est, 'provider.est');
    return { protocol: 'est', server: provider.est, label: provider.label || null, ca: provider.ca || null };
  }
  throw new Error('provider: a name, { acme: url } or { est: url }');
}

function checkUrl(u, what) {
  let parsed;
  try { parsed = new URL(u); } catch (e) { throw new Error(what + ' is not a URL: ' + u); }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && what === 'provider.acme')) {
    throw new Error(what + ' must be https: ' + u);
  }
}

export { PROVIDERS, resolveProvider };
export default PROVIDERS;
