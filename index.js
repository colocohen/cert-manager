
import Order from './src/order.js';
import Manager from './src/manager.js';
import { PROVIDERS } from './src/providers.js';
import {
  generateKey,
  getJwk,
  getJwkThumbprint,
  createCsr,
  signJws,
  signEab,
  base64url,
  pemEncode,
  toAsciiDomain,
  ipToBytes,
  ipToArpa,
  createAlpnCertificate,
  getAriCertId,
} from './src/crypto.js';
import { AcmeHttp } from './src/http.js';
import {
  verifyDnsChallenge,
  verifyHttpChallenge,
  checkCaa,
} from './src/verify.js';


function createOrder(options) {
  return new Order(options);
}

function manager(options) {
  return new Manager(options);
}


/**
 * Crypto primitives for advanced consumers.
 */
const crypto = {
  generateKey,
  getJwk,
  getJwkThumbprint,
  createCsr,
  signJws,
  signEab,
  base64url,
  pemEncode,
  toAsciiDomain,
  ipToBytes,
  ipToArpa,
  createAlpnCertificate,
  getAriCertId,
};


/**
 * Verification utilities.
 */
const verify = {
  verifyDnsChallenge,
  verifyHttpChallenge,
  checkCaa,
};


export {
  createOrder,
  manager,
  Order,
  Manager,
  PROVIDERS,
  AcmeHttp,
  crypto,
  verify,
};


export default {
  createOrder,
  manager,
  Order,
  Manager,
  PROVIDERS,
  AcmeHttp,
  crypto,
  verify,
};
