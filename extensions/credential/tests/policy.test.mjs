// Policy decisions are security decisions: a wrong "allowed" hands a
// credential to a page that should not have it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAllowed, isStale, DEFAULT_POLICY } from '../src/background/policy.js';

test('the default policy allows nothing', () => {
  assert.equal(isAllowed('https://example.com/login', DEFAULT_POLICY), false);
});

test('a missing policy allows nothing', () => {
  assert.equal(isAllowed('https://example.com/login', null), false);
  assert.equal(isAllowed('https://example.com/login', undefined), false);
});

test('deny wins over allow', () => {
  const policy = { enable: ['example.com'], disable: ['*', 'example.com'] };
  assert.equal(isAllowed('https://example.com/', policy), false);
});

test('an enabled host is allowed', () => {
  const policy = { enable: ['example.com'], disable: [] };
  assert.equal(isAllowed('https://example.com/login', policy), true);
});

test('a subdomain of an enabled host is allowed', () => {
  const policy = { enable: ['example.com'], disable: [] };
  assert.equal(isAllowed('https://shop.example.com/', policy), true);
});

test('a different host is not allowed', () => {
  const policy = { enable: ['example.com'], disable: [] };
  assert.equal(isAllowed('https://other.test/', policy), false);
});

test('a malformed url is not allowed', () => {
  const policy = { enable: ['example.com'], disable: [] };
  assert.equal(isAllowed('not a url', policy), false);
});

test('a stale policy is treated as stale', () => {
  assert.equal(isStale({ now_ms: 1000 }, 2000, 500), true);
  assert.equal(isStale({ now_ms: 1000 }, 1200, 500), false);
  assert.equal(isStale(null, 2000, 500), true);
});
