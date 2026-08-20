// The data-collection consent decision, src/ext/consent.js.
//
// The defect this pins: consentToSync never asked whether the permission was
// already held, so every failure of permissions.request() — which needs a live
// user gesture and can fail for reasons that have nothing to do with consent —
// read as a refusal. A machine with every toggle already on in about:addons
// could not join a server, and the error sent its person to the settings page
// where everything was already granted.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { syncConsent } from '../src/ext/consent.js';

const WANTED = ['authenticationInfo', 'personallyIdentifyingInfo'];

test('a permission already held is a yes, and no prompt is raised', async () => {
  let requested = 0;
  const api = {
    contains: async (q) => {
      assert.deepEqual(q, { data_collection: WANTED });
      return true;
    },
    request: async () => {
      requested++;
      // The exact failure from the field: request() breaking on a machine
      // whose permission is already granted. It must never be reached.
      throw new Error('request failed for its own reasons');
    },
  };

  assert.deepEqual(await syncConsent(api, WANTED), { ok: true });
  assert.equal(requested, 0, 'request() was called for a permission already held');
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

test('the prompt failing is an error, named as itself and never as a refusal', async () => {
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

test('contains() failing falls through to the request rather than denying', async () => {
  const api = {
    contains: async () => {
      throw new Error('contains broke');
    },
    request: async () => true,
  };
  assert.deepEqual(await syncConsent(api, WANTED), { ok: true });
});

test('outside the extension there is nothing to ask and nothing to gate', async () => {
  assert.deepEqual(await syncConsent(undefined, WANTED), { ok: true });
  assert.deepEqual(await syncConsent({ request: async () => false }, []), { ok: true });
  // An api without contains (older shape) still works: straight to the ask.
  assert.deepEqual(await syncConsent({ request: async () => true }, WANTED), { ok: true });
});
