
/**
 * Minimal ASN.1 DER encoder/decoder for ACME CSR generation.
 */


function encode_length(len) {
  if (len < 0x80) {
    return new Uint8Array([len]);
  }
  let bytes = [];
  let tmp = len;
  while (tmp > 0) {
    bytes.unshift(tmp & 0xFF);
    tmp = tmp >>> 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function encode_tag(tag, content) {
  let len = encode_length(content.length);
  let out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

// Concatenate multiple Uint8Arrays into one
function concat_parts(parts) {
  let total = 0;
  for (let i = 0; i < parts.length; i++) total += parts[i].length;
  let content = new Uint8Array(total);
  let off = 0;
  for (let i = 0; i < parts.length; i++) {
    content.set(parts[i], off);
    off += parts[i].length;
  }
  return content;
}

// ASN.1 types
function SEQUENCE(parts) {
  return encode_tag(0x30, concat_parts(parts));
}

function SET(parts) {
  return encode_tag(0x31, concat_parts(parts));
}

function INTEGER(value) {
  if (typeof value === 'number') {
    if (value === 0) return encode_tag(0x02, new Uint8Array([0]));
    let bytes = [];
    let tmp = value;
    while (tmp > 0) {
      bytes.unshift(tmp & 0xFF);
      tmp = tmp >>> 8;
    }
    if (bytes[0] & 0x80) bytes.unshift(0);
    return encode_tag(0x02, new Uint8Array(bytes));
  }
  // Uint8Array
  let arr = value;
  if (arr[0] & 0x80) {
    let padded = new Uint8Array(arr.length + 1);
    padded[0] = 0;
    padded.set(arr, 1);
    arr = padded;
  }
  return encode_tag(0x02, arr);
}

function BIT_STRING(content) {
  let out = new Uint8Array(1 + content.length);
  out[0] = 0x00; // no unused bits
  out.set(content, 1);
  return encode_tag(0x03, out);
}

function OCTET_STRING(content) {
  return encode_tag(0x04, content);
}

function OID(oid_str) {
  let parts = oid_str.split('.').map(Number);
  let bytes = [];
  bytes.push(parts[0] * 40 + parts[1]);
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i];
    if (val < 128) {
      bytes.push(val);
    } else {
      let tmp = [];
      tmp.push(val & 0x7F);
      val = val >>> 7;
      while (val > 0) {
        tmp.push(0x80 | (val & 0x7F));
        val = val >>> 7;
      }
      tmp.reverse();
      for (let j = 0; j < tmp.length; j++) bytes.push(tmp[j]);
    }
  }
  return encode_tag(0x06, new Uint8Array(bytes));
}

function UTF8STRING(str) {
  return encode_tag(0x0C, new TextEncoder().encode(str));
}

// X.520 mandates PrintableString for countryName (C)
function PRINTABLESTRING(str) {
  return encode_tag(0x13, new TextEncoder().encode(str));
}

// ASN.1 NULL — required parameter for RSA AlgorithmIdentifier (RFC 5754)
function ASN1_NULL() {
  return encode_tag(0x05, new Uint8Array(0));
}

// ASN.1 BOOLEAN — DER requires TRUE to be exactly 0xFF
function BOOLEAN(value) {
  return encode_tag(0x01, new Uint8Array([value ? 0xFF : 0x00]));
}

// UTCTime 'YYMMDDHHMMSSZ' — X.509 mandates UTCTime for dates before 2050
// (GeneralizedTime after). Challenge certs live for hours, so UTCTime suffices.
function UTCTIME(date) {
  function p2(n) { return (n < 10 ? '0' : '') + n; }
  let s = p2(date.getUTCFullYear() % 100) + p2(date.getUTCMonth() + 1) + p2(date.getUTCDate()) +
          p2(date.getUTCHours()) + p2(date.getUTCMinutes()) + p2(date.getUTCSeconds()) + 'Z';
  return encode_tag(0x17, new TextEncoder().encode(s));
}

function IA5STRING(str) {
  return encode_tag(0x16, new TextEncoder().encode(str));
}

function EXPLICIT(tag_num, content) {
  return encode_tag(0xA0 | tag_num, content);
}

/**
 * Minimal DER TLV reader (the encoder's counterpart).
 * Returns { tag, start, end, next }:
 *   tag   — the tag byte
 *   start — offset of the first content byte
 *   end   — offset just past the content
 *   next  — offset of the next sibling TLV (== end)
 */
function read_tlv(u8, off) {
  let tag = u8[off];
  let len = u8[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    let n = len & 0x7F;
    len = 0;
    for (let i = 0; i < n; i++) len = (len * 256) + u8[off + 2 + i];
    hdr = 2 + n;
  }
  return { tag: tag, start: off + hdr, end: off + hdr + len, next: off + hdr + len };
}


// Well-known OIDs
const OID_COMMON_NAME = '2.5.4.3';
const OID_COUNTRY = '2.5.4.6';
const OID_STATE = '2.5.4.8';
const OID_LOCALITY = '2.5.4.7';
const OID_ORGANIZATION = '2.5.4.10';
const OID_ORG_UNIT = '2.5.4.11';
const OID_EMAIL = '1.2.840.113549.1.9.1';
const OID_SAN = '2.5.29.17';   // subjectAltName
const OID_EXTENSION_REQUEST = '1.2.840.113549.1.9.14'; // extensionRequest
const OID_ACME_IDENTIFIER = '1.3.6.1.5.5.7.1.31';       // id-pe-acmeIdentifier (RFC 8737)

// Signature algorithm OIDs
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const OID_SHA256_RSA = '1.2.840.113549.1.1.11';
const OID_SHA384_RSA = '1.2.840.113549.1.1.12';

// Key algorithm OIDs
const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1';
const OID_RSA_PUBLIC_KEY = '1.2.840.113549.1.1.1';
const OID_P256 = '1.2.840.10045.3.1.7';
const OID_P384 = '1.3.132.0.34';


export {
  encode_length,
  encode_tag,
  concat_parts,
  SEQUENCE,
  SET,
  INTEGER,
  BIT_STRING,
  OCTET_STRING,
  OID,
  UTF8STRING,
  IA5STRING,
  PRINTABLESTRING,
  ASN1_NULL,
  BOOLEAN,
  UTCTIME,
  EXPLICIT,
  read_tlv,
  OID_COMMON_NAME,
  OID_COUNTRY,
  OID_STATE,
  OID_LOCALITY,
  OID_ORGANIZATION,
  OID_ORG_UNIT,
  OID_EMAIL,
  OID_SAN,
  OID_EXTENSION_REQUEST,
  OID_ACME_IDENTIFIER,
  OID_ECDSA_SHA256,
  OID_ECDSA_SHA384,
  OID_SHA256_RSA,
  OID_SHA384_RSA,
  OID_EC_PUBLIC_KEY,
  OID_RSA_PUBLIC_KEY,
  OID_P256,
  OID_P384,
};
