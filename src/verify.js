
import * as dns from 'node:dns';

// Fallback resolver for when system DNS fails
let fallback_resolver = new dns.Resolver();
fallback_resolver.setServers(['8.8.8.8', '1.1.1.1']);


/**
 * Resolve with system DNS first, fallback to public DNS on failure.
 * method: 'resolveTxt' | 'resolveCaa'
 */
function resolveWithFallback(method, domain, callback) {
  dns[method](domain, function(err, records) {
    if (!err) return callback(null, records);

    // System DNS failed, try fallback
    fallback_resolver[method](domain, function(err2, records2) {
      callback(err2, records2);
    });
  });
}


/**
 * Verify that a DNS TXT record exists with the expected value.
 * callback(err, found)
 */
function verifyDnsChallenge(domain, expected_value, callback) {
  resolveWithFallback('resolveTxt', domain, function(err, records) {
    if (err) return callback(null, false);

    for (let i = 0; i < records.length; i++) {
      let joined = records[i].join('');
      if (joined === expected_value) {
        return callback(null, true);
      }
    }

    callback(null, false);
  });
}


/**
 * Check if CAA records allow a specific CA to issue certificates.
 * If no CAA records exist, any CA is allowed (RFC 8659).
 * callback(err, { exists, allowed, records })
 */
function checkCaa(domain, ca_domain, callback) {
  resolveWithFallback('resolveCaa', domain, function(err, records) {
    if (err || !records || records.length === 0) {
      return callback(null, { exists: false, allowed: true, records: [] });
    }

    let allowed = false;
    let raw = [];

    for (let i = 0; i < records.length; i++) {
      raw.push({
        critical: records[i].critical || 0,
        tag: records[i].issue || records[i].issuewild ? (records[i].issuewild ? 'issuewild' : 'issue') : (records[i].iodef ? 'iodef' : 'unknown'),
        value: records[i].issue || records[i].issuewild || records[i].iodef || '',
      });

      let value = records[i].issue || records[i].issuewild || '';
      if (ca_domain && value.indexOf(ca_domain) >= 0) {
        allowed = true;
      }
    }

    callback(null, { exists: true, allowed: allowed, records: raw });
  });
}


export {
  verifyDnsChallenge,
  checkCaa,
};
