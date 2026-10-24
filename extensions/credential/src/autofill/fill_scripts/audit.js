// Fill script execution audit records.
//
// Constructs a frozen (immutable) audit event for one package execution and
// emits it on the `[lengsuo-fill]` console channel. The event never carries a
// credential value: selector names may be logged, values must not.
//
// ⚠ 每条改动必须同步更新 content/fill_script_content.js 的内联实现。

export function recordExecution({ package_id, version, hostname, actions_total, actions_done, ok, reason }) {
  const event = Object.freeze({
    timestamp: Date.now(),
    package_id,
    version,
    hostname,
    actions_total,
    actions_done,
    ok,
    reason: reason ?? null,
  });
  console.log('[lengsuo-fill]', JSON.stringify(event));
  return event;
}