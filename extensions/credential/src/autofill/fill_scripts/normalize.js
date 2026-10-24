// JCS (RFC 8785) canonical JSON serialization.
//
// Pure function: any JSON value -> canonical UTF-8 string. Keys are sorted by
// UTF-16 code unit order, no whitespace, numbers use shortest representation,
// strings use minimal escaping and non-ASCII characters are emitted as UTF-8.
//
// Used by verify.js to compute the exact bytes an Ed25519 signature covers.
//
// ⚠ 每条改动必须同步更新 content/fill_script_content.js 的内联实现：
// 两边必须对同一输入输出逐字节相同（见 fill_scripts.test.mjs）。

const ESCAPE = {
  0x08: '\\b', // \b
  0x09: '\\t', // \t
  0x0a: '\\n', // \n
  0x0c: '\\f', // \f
  0x0d: '\\r', // \r
  0x22: '\\"', // "
  0x5c: '\\\\', // \
};

export function normalize(value) {
  return encodeValue(value);
}

function encodeValue(value) {
  const type = typeof value;
  if (value === null) return 'null';
  if (type === 'boolean') return value ? 'true' : 'false';
  if (type === 'number') return encodeNumber(value);
  if (type === 'string') return encodeString(value);
  if (Array.isArray(value)) return encodeArray(value);
  if (type === 'object') return encodeObject(value);
  throw new Error(`cannot normalize value of type ${type}`);
}

function encodeNumber(n) {
  if (!Number.isFinite(n)) {
    throw new Error(`cannot normalize non-finite number ${n}`);
  }
  if (Object.is(n, -0)) return '0';
  return String(n);
}

function encodeString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i += 1) {
    const ch = s.charCodeAt(i);
    const esc = ESCAPE[ch];
    if (esc !== undefined) {
      out += esc;
    } else if (ch < 0x20) {
      out += '\\u' + ch.toString(16).padStart(4, '0');
    } else {
      out += s[i];
    }
  }
  return out + '"';
}

function encodeArray(arr) {
  let out = '[';
  for (let i = 0; i < arr.length; i += 1) {
    if (i > 0) out += ',';
    out += encodeValue(arr[i]);
  }
  return out + ']';
}

function encodeObject(obj) {
  const keys = Object.keys(obj).sort();
  let out = '{';
  for (let i = 0; i < keys.length; i += 1) {
    if (i > 0) out += ',';
    out += encodeString(keys[i]) + ':' + encodeValue(obj[keys[i]]);
  }
  return out + '}';
}
