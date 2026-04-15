
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
} from './src/crypto.js';
import { AcmeHttp } from './src/http.js';
import {
  verifyDnsChallenge,
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
var crypto = {
  generateKey,
  getJwk,
  getJwkThumbprint,
  createCsr,
  signJws,
  signEab,
  base64url,
};


/**
 * Verification utilities.
 */
var verify = {
  verifyDnsChallenge,
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
