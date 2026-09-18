// The data-collection consent decision, src/ext/consent.js.
//
// Two defects, one function, and they pull against each other.
//
// The first: consentToSync never asked whether the permission was already held,
// so every failure of permissions.request() — which can fail for reasons that
// have nothing to do with consent — read as a refusal. A machine with every
// toggle already on in about:addons could not join a server, and the error sent
// its person to the settings page where everything was already granted.
//
// The second was the fix for the first. Asking `contains` before `request`
// spends the user gesture that `request` requires, so a machine that had NOT
// already granted the permission — every fresh install — got
// "permissions.request may only be called from a user input handler" and could
// not join either. Found by installing on a machine with no history, which is
// the one case a year of daily use on a configured machine never produces.
//
// So the order is load-bearing in both directions, and `contains after request`
// is the only order that survives both. These pin it.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { syncConsent } from '../src/ext/consent.js';

const WANTED = ['authenticationInfo', 'personallyIdentifyingInfo'];

test('contains() is never consulted before request(), because asking spends the gesture', async () => {
  // The order, pinned directly. Reversing these two lines is the whole of the
  // 0.12.2 defect: every fresh install failed to join, with the browser saying
  // exactly what the mock says below.
  const calls = [];
  const api = {
    contains: async () => {
      calls.push('contains');
      return true;
    },
    request: async () => {
      calls.push('request');
      throw new Error('permissions.request may only be called from a user input handler');
    },
  };

  assert.deepEqual(await syncConsent(api, WANTED), { ok: true });
  assert.deepEqual(calls, ['request', 'contains'], 'contains() ran before request()');
});

test('a permission already held is a yes even when the prompt breaks', async () => {
  // The first defect, still pinned: request() failing on a machine whose
  // permission is granted must not read as a refusal. It is now answered
  // after the fact rather than avoided beforehand.
  const api = {
    contains: async (q) => {
      assert.deepEqual(q, { data_collection: WANTED });
      return true;
    },
    request: async () => {
      throw new Error('request failed for its own reasons');
    },
  };

  assert.deepEqual(await syncConsent(api, WANTED), { ok: true });
});

test('a permission already held raises no prompt of its own', async () => {
  // request() on a held permission resolves true without drawing anything,
  // which is what makes asking first free.
  const api = {
    contains: async () => {
      throw new Error('contains must not be needed here');
    },
    request: async () => true,
  };

  assert.deepEqual(await syncConsent(api, WANTED), { ok: true });
});

test('a permission not yet held is requested, and a grant is a yes', async () => {
  let asked = null;
  const api = {
    contains: async () => false,
    request: async (q) => {
      asked = q;
      return true;
    },
  };

  assert.deepEqual(await syncConsent(api, WANTED), { ok: true });
  assert.deepEqual(asked, { data_collection: WANTED });
});

test('declining the prompt is a refusal, named as one', async () => {
  const api = { contains: async () => false, request: async () => false };
  assert.deepEqual(await syncConsent(api, WANTED), { ok: false, reason: 'refused' });
});

test('the prompt failing on a machine that never granted it is an error', async () => {
  // Not held, and the prompt broke: the one case that is genuinely an error.
  const api = {
    contains: async () => false,
    request: async () => {
      throw new Error('spent gesture');
    },
  };
  const verdict = await syncConsent(api, WANTED);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'error');
  assert.match(verdict.message, /spent gesture/);
});

test('contains() failing decides nothing either way', async () => {
  const granted = {
    contains: async () => {
      throw new Error('contains broke');
    },
    request: async () => true,
  };
  assert.deepEqual(await syncConsent(granted, WANTED), { ok: true });

  // And when the request broke too, the error is the request's, reported as
  // itself rather than as a refusal nobody made.
  const broken = {
    contains: async () => {
      throw new Error('contains broke');
    },
    request: async () => {
      throw new Error('spent gesture');
    },
  };
  const verdict = await syncConsent(broken, WANTED);
  assert.equal(verdict.ok, false);
  assert.equal(verdict.reason, 'error');
});

test('outside the extension there is nothing to ask and nothing to gate', async () => {
  assert.deepEqual(await syncConsent(undefined, WANTED), { ok: true });
  assert.deepEqual(await syncConsent({ request: async () => false }, []), { ok: true });
  // An api without contains (older shape) still works: straight to the ask.
  assert.deepEqual(await syncConsent({ request: async () => true }, WANTED), { ok: true });
});
