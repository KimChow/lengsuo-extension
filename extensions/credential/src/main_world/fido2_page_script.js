// Main world script: intercepts navigator.credentials.
//
// It wraps create and get, answers from the managed credential when the host
// has one, and otherwise falls through to the browser's own implementation.
// Falling through is what keeps a page usable when the host is missing.
//
// The managed response is only trusted after the page has checked it itself:
// the nonce must echo the request (anti-replay, §5.1), and the clientDataJSON
// the host built must name this origin and this challenge (anti-phishing,
// §5.3.1). A response that fails those checks is rejected, never turned into a
// native fallback: a mismatched channel is not "no credential here".
//
// No imports: this file is injected into the page's world as-is.

(function () {
  const CHANNEL = 'lengsuo-fido2';
  // Captured before the page can replace them: these are the fallback path.
  const NATIVE = [
    navigator.credentials.create.bind(navigator.credentials),
    navigator.credentials.get.bind(navigator.credentials),
  ];

  const TYPE_CREATE = 3;
  const TYPE_GET = 4;
  const TYPES = {
    LIST_CREDENTIALS: 0,
    GET_PASSWORD: 1,
    GET_TOTP: 2,
    PASSKEY_CREATE: 3,
    PASSKEY_GET: 4,
    SAVE_PASSWORD: 5,
  };

  // ---- base64url (payload fields, §5.3.1) ---------------------------------
  //
  // The envelope layer uses standard base64 (native_bridge.js). Payload
  // fields use base64url with no padding. Keep the two separate.

  function b64urlEncode(input) {
    let bytes;
    if (input instanceof Uint8Array) bytes = input;
    else if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
    else throw new TypeError('b64urlEncode expects a Uint8Array or ArrayBuffer');

    // Chunked: String.fromCharCode.apply over a large array overflows.
    const chunk = 0x8000;
    let binary = '';
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlDecode(text) {
    if (typeof text !== 'string' || text.length === 0) {
      throw new TypeError('b64urlDecode expects a non-empty string');
    }
    let padding = 0;
    if (text.endsWith('==')) padding = 2;
    else if (text.endsWith('=')) padding = 1;
    const body = text.slice(0, text.length - padding);

    if (body.includes('=') || !/^[A-Za-z0-9_-]+$/.test(body)) {
      throw new Error('b64urlDecode: invalid base64url input');
    }
    if (body.length % 4 === 1) {
      throw new Error('b64urlDecode: impossible length');
    }

    const standard = body.replace(/-/g, '+').replace(/_/g, '/');
    const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  }

  // ---- nonce (§5.3.1: decimal integer) ------------------------------------

  function newNonce() {
    return crypto.getRandomValues(new Uint32Array(1))[0];
  }

  // ---- request construction (§5.3.1) --------------------------------------

  function buildCreateRequest(options) {
    return {
      nonce: newNonce(),
      origin: location.origin,
      rp_id: options.rp.id,
      challenge: b64urlEncode(options.challenge),
      user: {
        id: b64urlEncode(options.user.id),
        name: options.user.name,
        display_name: options.user.displayName,
      },
    };
  }

  function buildGetRequest(options) {
    return {
      nonce: newNonce(),
      origin: location.origin,
      rp_id: options.rpId,
      challenge: b64urlEncode(options.challenge),
      allow_ids: (options.allowCredentials ?? []).map((c) => b64urlEncode(c.id)),
    };
  }

  // ---- channel ------------------------------------------------------------

  function post(type, payload) {
    return new Promise((resolve) => {
      const id = Math.random().toString(36).slice(2);
      const onMessage = (event) => {
        if (event.source !== window) return;
        const data = event.data;
        if (!data || data.channel !== CHANNEL || data.id !== id) return;
        window.removeEventListener('message', onMessage);
        resolve(data.result);
      };
      window.addEventListener('message', onMessage);
      window.postMessage({ channel: CHANNEL, id, type, payload }, '*');
    });
  }

  // ---- managed response validation ----------------------------------------

  function decodeManaged(result) {
    if (!result || result.ok !== true || result.use_native === true) return null;
    const bytes = result.payload;
    if (!(bytes instanceof Uint8Array)) {
      throw new Error('bad_response: payload is not a Uint8Array');
    }
    return JSON.parse(new TextDecoder().decode(bytes));
  }

  function parseClientData(response) {
    const raw = b64urlDecode(response.client_data_json_b64);
    return JSON.parse(new TextDecoder().decode(raw));
  }

  function verifyManaged(request, response) {
    if (!response || typeof response !== 'object' || Array.isArray(response)) {
      throw new Error('bad_response: response is not an object');
    }
    if (response.nonce !== request.nonce) {
      throw new Error('nonce mismatch: response belongs to another request');
    }
    const clientData = parseClientData(response);
    if (clientData.origin !== location.origin) {
      throw new Error('origin mismatch: refusing a credential for another origin');
    }
    if (clientData.challenge !== request.challenge) {
      throw new Error('challenge mismatch: refusing a replayed response');
    }
  }

  // ---- CBOR: just the subset attestationObject needs (§3) ------------------

  function cborHead(major, length) {
    if (length < 24) return [major | length];
    if (length < 0x100) return [major | 24, length];
    if (length < 0x10000) return [major | 25, (length >>> 8) & 0xff, length & 0xff];
    return [major | 26, (length >>> 24) & 0xff, (length >>> 16) & 0xff, (length >>> 8) & 0xff, length & 0xff];
  }

  function cborText(text) {
    const bytes = new TextEncoder().encode(text);
    return [...cborHead(0x60, bytes.length), ...bytes];
  }

  function cborBytes(bytes) {
    return [...cborHead(0x40, bytes.length), ...bytes];
  }

  /** attestationObject = CBOR { "fmt": "none", "attStmt": {}, "authData": bstr }. */
  function encodeAttestationObject(authData) {
    const parts = [
      [0xa3], // map(3)
      cborText('fmt'),
      cborText('none'),
      cborText('attStmt'),
      [0xa0], // empty map
      cborText('authData'),
      cborBytes(authData),
    ];
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  // ---- response wrapping (§5.3.1 + reverse-doc behavior) ------------------

  function setProto(obj, ctor) {
    if (typeof ctor === 'function' && ctor.prototype) {
      try {
        Object.setPrototypeOf(obj, ctor.prototype);
      } catch {
        // A page may freeze its own prototypes; the object is still usable.
      }
    }
  }

  function wrapCreation(response) {
    const clientDataJSON = b64urlDecode(response.client_data_json_b64);
    const authData = b64urlDecode(response.auth_data_b64);
    const rawId = b64urlDecode(response.credential_id);
    const attestationObject = encodeAttestationObject(authData);

    const responseObj = {
      clientDataJSON,
      attestationObject,
      getTransports: () => [],
      getAuthenticatorData: () => authData,
      getPublicKey: () => null, // Never fabricate an SPKI we do not have.
      getPublicKeyAlgorithm: () => -7,
    };
    setProto(
      responseObj,
      typeof AuthenticatorAttestationResponse !== 'undefined'
        ? AuthenticatorAttestationResponse
        : undefined,
    );

    const cred = {
      id: response.credential_id,
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: responseObj,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({
        id: response.credential_id,
        rawId: b64urlEncode(rawId),
        type: 'public-key',
        response: {
          clientDataJSON: b64urlEncode(clientDataJSON),
          attestationObject: b64urlEncode(attestationObject),
        },
      }),
    };
    setProto(cred, typeof PublicKeyCredential !== 'undefined' ? PublicKeyCredential : undefined);
    return cred;
  }

  function wrapAssertion(response) {
    const clientDataJSON = b64urlDecode(response.client_data_json_b64);
    const authenticatorData = b64urlDecode(response.auth_data_b64);
    const signature = b64urlDecode(response.signature_b64);
    const userHandle = response.user_handle ? b64urlDecode(response.user_handle) : null;

    const responseObj = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };
    setProto(
      responseObj,
      typeof AuthenticatorAssertionResponse !== 'undefined'
        ? AuthenticatorAssertionResponse
        : undefined,
    );

    const cred = {
      id: response.credential_id,
      rawId: response.credential_id ? b64urlDecode(response.credential_id) : null,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: responseObj,
      getClientExtensionResults: () => ({}),
      toJSON: () => ({
        id: response.credential_id,
        rawId: response.credential_id ? response.credential_id : null,
        type: 'public-key',
        response: {
          clientDataJSON: b64urlEncode(clientDataJSON),
          authenticatorData: b64urlEncode(authenticatorData),
          signature: b64urlEncode(signature),
          userHandle: userHandle ? b64urlEncode(userHandle) : null,
        },
      }),
    };
    setProto(cred, typeof PublicKeyCredential !== 'undefined' ? PublicKeyCredential : undefined);
    return cred;
  }

  // ---- interception --------------------------------------------------------

  function fallback(native, args) {
    return native.apply(navigator.credentials, args);
  }

  async function proxy(native, type, args) {
    const options = args[0] ?? {};

    let request;
    try {
      request = type === TYPE_CREATE ? buildCreateRequest(options) : buildGetRequest(options);
    } catch {
      // The page passed options we cannot encode; native will reject them the
      // same way.
      return fallback(native, args);
    }

    let result;
    try {
      result = await post(type, request);
    } catch {
      return fallback(native, args);
    }

    // Transport failure or an explicit UseNativeResponse: keep the page usable.
    let response;
    try {
      response = decodeManaged(result);
    } catch {
      // A managed reply we cannot even parse is a broken channel, not absence.
      throw new Error('bad_response: managed reply is not valid JSON');
    }
    if (response === null) return fallback(native, args);

    // Any failure below is thrown on purpose: do not disguise a mismatched
    // channel as "no managed credential".
    verifyManaged(request, response);
    return type === TYPE_CREATE ? wrapCreation(response) : wrapAssertion(response);
  }

  navigator.credentials.create = function (...args) {
    return proxy(NATIVE[0], TYPE_CREATE, args);
  };
  navigator.credentials.get = function (...args) {
    return proxy(NATIVE[1], TYPE_GET, args);
  };

  // ---- password / TOTP request entry points (W7 consumes these) -----------
  //
  // These only build requests and return the host's JSON answer. No DOM work.

  async function requestJson(type, payload) {
    const result = await post(type, payload);
    if (!result || result.ok !== true || result.use_native === true) return null;
    if (!(result.payload instanceof Uint8Array)) return null;
    return JSON.parse(new TextDecoder().decode(result.payload));
  }

  window.__lengsuoCredential = {
    list() {
      return requestJson(TYPES.LIST_CREDENTIALS, { nonce: newNonce(), origin: location.origin });
    },
    getPassword({ username } = {}) {
      return requestJson(TYPES.GET_PASSWORD, {
        nonce: newNonce(),
        origin: location.origin,
        username: username ?? null,
      });
    },
    savePassword({ username, password } = {}) {
      return requestJson(TYPES.SAVE_PASSWORD, {
        nonce: newNonce(),
        origin: location.origin,
        username: username ?? null,
        password: password ?? null,
      });
    },
    getTotp({ ref } = {}) {
      return requestJson(TYPES.GET_TOTP, {
        nonce: newNonce(),
        origin: location.origin,
        ref: ref ?? null,
      });
    },
  };

  // Test hook: only fires when a test installs the global.
  if (typeof globalThis.__LENGSUO_PAGE_TEST_HOOK__ === 'function') {
    globalThis.__LENGSUO_PAGE_TEST_HOOK__({
      b64urlEncode,
      b64urlDecode,
      buildCreateRequest,
      buildGetRequest,
      wrapCreation,
      wrapAssertion,
    });
  }
})();
