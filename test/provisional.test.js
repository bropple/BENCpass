// A generated password must exist somewhere the moment it exists at all.
//
// The failure these tests pin: accept a generated password on a sign-up form,
// miss the save toast (it is drawn into the page the submit navigates away
// from), close the tab — and the site holds a password nobody knows. So
// generating writes a provisional entry first, and submitting completes it.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Vault } from '../src/core/vault.js';
import { keepGenerated, completeGenerated } from '../src/core/provisional.js';
import { captureTarget } from '../src/core/match.js';

const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };
const mk = () => Vault.create({ password: 'hunter2', kdf: FAST });

test('a generated password is saved before the page ever sees it', async () => {
  const v = await mk();
  const id = await keepGenerated(v, {
    host: 'shop.example',
    url: 'https://shop.example',
    password: 'gen-1',
  });

  const r = v.get(id);
  assert.equal(r.password, 'gen-1');
  assert.equal(r.title, 'shop.example');
  assert.equal(r.provisional, true);
  assert.deepEqual(r.urls, ['https://shop.example']);

  // And it survives the exact sequence that used to lose it: lock, reload.
  const reloaded = Vault.load(v.toJSON());
  await reloaded.unlock('hunter2');
  assert.equal(reloaded.get(id).password, 'gen-1');
});

test('regenerating replaces the provisional entry instead of stacking duplicates', async () => {
  const v = await mk();
  const first = await keepGenerated(v, { host: 'shop.example', url: 'https://shop.example', password: 'gen-1' });
  const second = await keepGenerated(v, { host: 'shop.example', url: 'https://shop.example', password: 'gen-2' });

  assert.equal(first, second);
  assert.equal(v.list().length, 1);
  // The last one generated is the one in the field, so it is the one kept.
  assert.equal(v.get(first).password, 'gen-2');
});

test('a page with no host still gets its password kept', async () => {
  const v = await mk();
  const id = await keepGenerated(v, { host: '', url: '', password: 'gen-1' });
  assert.equal(v.get(id).title, 'Generated password');
  assert.deepEqual(v.get(id).urls, []);

  // And regenerating there replaces too.
  assert.equal(await keepGenerated(v, { host: '', url: '', password: 'gen-2' }), id);
  assert.equal(v.list().length, 1);
});

test('captureTarget surfaces the provisional entry so the submit can complete it', async () => {
  const v = await mk();
  const id = await keepGenerated(v, { host: 'shop.example', url: 'https://shop.example', password: 'gen-1' });

  // The submit arrives with a username the record never had; the plain
  // candidate match therefore misses, and this is the field that catches it.
  const { candidate, provisional } = captureTarget(v.list(), 'shop.example', 'ben@ropple.net');
  assert.equal(candidate, null);
  assert.equal(provisional?.id, id);

  // A different site's capture must not land on it.
  assert.equal(captureTarget(v.list(), 'other.example', 'ben').provisional, null);
});

test('completing attaches the username and drops the provisional mark', async () => {
  const v = await mk();
  const id = await keepGenerated(v, { host: 'shop.example', url: 'https://shop.example', password: 'gen-1' });

  await completeGenerated(v, v.get(id), 'ben@ropple.net');
  const r = v.get(id);
  assert.equal(r.username, 'ben@ropple.net');
  assert.equal(r.provisional, false);
  assert.equal(r.password, 'gen-1');
  // Completing is not a password change; nothing lands in the history.
  assert.deepEqual(r.history, []);

  // Once completed it is an ordinary entry: no capture lands on it as
  // provisional again.
  assert.equal(captureTarget(v.list(), 'shop.example', 'someone-else').provisional, null);
});
