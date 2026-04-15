// CommonJS wrapper for cert-manager
// Dynamically imports the ESM module

let _module = null;
let _pending = null;

function loadModule() {
  if (_module) return Promise.resolve(_module);
  if (_pending) return _pending;
  _pending = import('./index.js').then(function(m) {
    _module = m.default || m;
    return _module;
  });
  return _pending;
}

// Synchronous access after first load
function getModule() {
  if (!_module) throw new Error('cert-manager: module not loaded yet. Use require("cert-manager").then() or await import("cert-manager").');
  return _module;
}

// Pre-load on require
loadModule();

module.exports = {
  createOrder: function(options) { return getModule().createOrder(options); },
  manager: function(options) { return getModule().manager(options); },
  get crypto() { return getModule().crypto; },
  get verify() { return getModule().verify; },
  get PROVIDERS() { return getModule().PROVIDERS; },
  get Order() { return getModule().Order; },
  get Manager() { return getModule().Manager; },
  then: function(fn) { return loadModule().then(fn); },
};
