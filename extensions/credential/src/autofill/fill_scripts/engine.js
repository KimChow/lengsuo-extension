// Fill script action interpreter.
//
// Pure function core: interprets a validated action sequence against an api
// supplied by the host environment (content script or test). Never touches the
// DOM directly; every side effect goes through `api`.
//
// fail-closed: the first action whose result is ok:false stops the sequence
// and is reported as `failed_at`. A failed step is never skipped.
//
// ⚠ 每条改动必须同步更新 content/fill_script_content.js 的内联实现。

const REQUIRED_API = ['setValue', 'click', 'wait', 'readText', 'getCredential'];

export function runActions(actions, api) {
  for (const name of REQUIRED_API) {
    if (typeof api[name] !== 'function') {
      throw new Error(`missing_api:${name}`);
    }
  }

  const results = [];
  for (let i = 0; i < actions.length; i += 1) {
    const action = actions[i];
    const result = runOne(action, api);
    results.push({ index: i, action: action.action, ...result });
    if (result.ok === false) {
      return { ok: false, failed_at: i, results };
    }
  }
  return { ok: true, results };
}

function runOne(action, api) {
  switch (action.action) {
    case 'set_value': {
      const value = api.getCredential(action.value_ref);
      return api.setValue(action.selector, value);
    }
    case 'fill_credentials': {
      const fields = [];
      for (const key of Object.keys(action.fields)) {
        const step = api.setValue(action.fields[key], api.getCredential(key));
        fields.push({ field: key, ok: step.ok, reason: step.reason });
        if (step.ok === false) return { ok: false, fields };
      }
      return { ok: true, fields };
    }
    case 'click':
      return api.click(action.selector);
    case 'wait':
      return api.wait(action.ms);
    case 'read_text':
      return { ...api.readText(action.selector), selector: action.selector };
    default:
      return { ok: false, reason: 'unknown_action' };
  }
}