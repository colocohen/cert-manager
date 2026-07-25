
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
 * Parse the CA domain out of a CAA issue/issuewild value.
 * Values may carry parameters: 'letsencrypt.org; validationmethods=dns-01'
 * An empty value ("") means "no CA may issue".
 */
function parseCaaIssueValue(value) {
  return String(value == null ? '' : value).split(';')[0].trim().toLowerCase();
}

/**
 * Detect which property a CAA record object carries.
 * Uses `in` checks — an empty string ('issue ""') is falsy but still a valid record.
 */
function caaTag(record) {
  if ('issuewild' in record && record.issuewild !== undefined) return 'issuewild';
  if ('issue' in record && record.issue !== undefined) return 'issue';
  if ('iodef' in record && record.iodef !== undefined) return 'iodef';
  return 'unknown';
}

/**
 * Evaluate a CAA record set against a CA domain per RFC 8659.
 * wildcard: when true, issuewild records take precedence over issue records.
 */
function evaluateCaa(records, ca_domain, wildcard) {
  let raw = [];
  let issue_values = [];
  let issuewild_values = [];

  for (let i = 0; i < records.length; i++) {
    let tag = caaTag(records[i]);
    let value = records[i][tag] !== undefined ? records[i][tag] : '';

    raw.push({
      critical: records[i].critical || 0,
      tag: tag,
      value: value,
    });

    if (tag === 'issue') issue_values.push(parseCaaIssueValue(value));
    if (tag === 'issuewild') issuewild_values.push(parseCaaIssueValue(value));
  }

  // RFC 8659 §4.3: for wildcard requests use issuewild if present, otherwise issue.
  // For non-wildcard requests use issue only.
  let relevant = wildcard
    ? (issuewild_values.length > 0 ? issuewild_values : issue_values)
    : issue_values;

  // CAA records exist but none restrict issuance (e.g. only iodef) → allowed.
  if (relevant.length === 0) {
    return { exists: true, allowed: true, records: raw };
  }

  // Exact match on the CA domain — never substring (indexOf would also match
  // 'letsencrypt.org.attacker.com'). Empty values ('issue "";') match nothing.
  let ca = String(ca_domain || '').toLowerCase();
  let allowed = false;
  for (let i = 0; i < relevant.length; i++) {
    if (ca && relevant[i] === ca) { allowed = true; break; }
  }

  return { exists: true, allowed: allowed, records: raw };
}

/**
 * Check if CAA records allow a specific CA to issue certificates.
 * Per RFC 8659, climbs the DNS tree: sub.example.com → example.com,
 * using the first CAA record set found. If none exist anywhere, any CA is allowed.
 *
 * checkCaa(domain, ca_domain, callback)
 * checkCaa(domain, ca_domain, { wildcard: true }, callback)
 *
 * callback(err, { exists, allowed, records, foundAt })
 */
function checkCaa(domain, ca_domain, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  let wildcard = !!options.wildcard;

  // Strip a leading wildcard label — CAA lookup starts at the base name
  let base = String(domain || '').replace(/^\*\./, '');
  let labels = base.split('.');

  function tryLevel(idx) {
    // Stop before the TLD (querying 'com' for CAA is pointless)
    if (labels.length - idx < 2) {
      return callback(null, { exists: false, allowed: true, records: [], foundAt: null });
    }

    let name = labels.slice(idx).join('.');

    resolveWithFallback('resolveCaa', name, function(err, records) {
      if (err || !records || records.length === 0) {
        return tryLevel(idx + 1);
      }
      let result = evaluateCaa(records, ca_domain, wildcard);
      result.foundAt = name;
      callback(null, result);
    });
  }

  tryLevel(0);
}


export {
  verifyDnsChallenge,
  checkCaa,
};
