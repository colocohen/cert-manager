
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

// ASN.1 types
function SEQUENCE(parts) {
  let total = 0;
  for (let i = 0; i < parts.length; i++) total += parts[i].length;
  let content = new Uint8Array(total);
  let off = 0;
  for (let i = 0; i < parts.length; i++) {
    content.set(parts[i], off);
    off += parts[i].length;
  }
  return encode_tag(0x30, content);
}

function SET(parts) {
  let total = 0;
  for (let i = 0; i < parts.length; i++) total += parts[i].length;
  let content = new Uint8Array(total);
  let off = 0;
  for (let i = 0; i < parts.length; i++) {
    content.set(parts[i], off);
    off += parts[i].length;
  }
  return encode_tag(0x31, content);
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

function IA5STRING(str) {
  return encode_tag(0x16, new TextEncoder().encode(str));
}

function EXPLICIT(tag_num, content) {
  return encode_tag(0xA0 | tag_num, content);
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
  SEQUENCE,
  SET,
  INTEGER,
  BIT_STRING,
  OCTET_STRING,
  OID,
  UTF8STRING,
  IA5STRING,
  EXPLICIT,
  OID_COMMON_NAME,
  OID_COUNTRY,
  OID_STATE,
  OID_LOCALITY,
  OID_ORGANIZATION,
  OID_ORG_UNIT,
  OID_EMAIL,
  OID_SAN,
  OID_EXTENSION_REQUEST,
  OID_ECDSA_SHA256,
  OID_ECDSA_SHA384,
  OID_SHA256_RSA,
  OID_SHA384_RSA,
  OID_EC_PUBLIC_KEY,
  OID_RSA_PUBLIC_KEY,
  OID_P256,
  OID_P384,
};
