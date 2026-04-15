
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

export { PROVIDERS };
export default PROVIDERS;
