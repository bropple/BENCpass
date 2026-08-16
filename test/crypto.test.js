import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_KDF,
  deriveMasterKey,
  importKey,
  newSalt,
  newVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  sealRecord,
  openRecord,
} from '../src/core/crypto.js';
import { toHex, fromHex, fromB64, toB64 } from '../src/core/bytes.js';

// Argon2 at its real settings costs 400 ms a call. Tests that only need *a* key
// use these instead. Anything asserting on the real parameters says so.
const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };

test('AES-256-GCM matches the specification test vector', async () => {
  // GCM specification, test case 14. This checks WebCrypto is wired up and that
  // the byte handling in bytes.js does not quietly mangle anything — a genuine
  // known-answer test, unlike the frozen vector below.
  const key = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(32),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  );
  const out = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: new Uint8Array(12) },
    key,
    new Uint8Array(16),
  );
  assert.equal(
    toHex(new Uint8Array(out)),
    // ciphertext ‖ tag
    'cea7403d4d606b6e074ec5d3baf39d18' + 'd0d1c8a799996bf0265b98b5d48ab919',
  );
});

test('Argon2id output is stable across versions of the dependency', async () => {
  // NOT an RFC known-answer test: hash-wasm exposes no `secret` or `associated
  // data` parameter, so RFC 9106's vector cannot be reproduced through it. This
  // is a frozen output, and its only job is to fail loudly if the library, its
  // wasm, or the parameters here ever change underneath an existing vault —
  // which would render every vault in the fleet unopenable.
  const key = await deriveMasterKey(
    'bencpass test vector',
    new Uint8Array(16).fill(0x02),
    { name: 'argon2id', memoryKiB: 1024, iterations: 2, parallelism: 1 },
  );
  assert.equal(
    toHex(key),
    '8bbb6c23bc9ef710b655b493456854932664d45efc615ca8adfbb75d8d360dc8',
  );
});

test('the shipped parameters are the ones that were measured', () => {
  assert.deepEqual(DEFAULT_KDF, {
    name: 'argon2id',
    memoryKiB: 131072,
    iterations: 3,
    parallelism: 1,
  });
});

test('a different salt gives a different key', async () => {
  const a = await deriveMasterKey('same password', newSalt(), FAST);
  const b = await deriveMasterKey('same password', newSalt(), FAST);
  assert.notEqual(toHex(a), toHex(b));
});

test('an unknown KDF is refused rather than substituted', async () => {
  await assert.rejects(
    () => deriveMasterKey('p', newSalt(), { name: 'pbkdf2' }),
    /unsupported kdf/,
  );
});

test('the vault key round-trips through a password wrapping', async () => {
  const master = await deriveMasterKey('hunter2', newSalt(), FAST);
  const vk = newVaultKey();
  const blob = await wrapVaultKey(vk, master, 'password');
  assert.equal(toHex(await unwrapVaultKey(blob, master)), toHex(vk));
});

test('the wrong master key cannot unwrap, and says nothing about why', async () => {
  const salt = newSalt();
  const right = await deriveMasterKey('hunter2', salt, FAST);
  const wrong = await deriveMasterKey('hunter3', salt, FAST);
  const blob = await wrapVaultKey(newVaultKey(), right, 'password');
  await assert.rejects(
    () => unwrapVaultKey(blob, wrong),
    // One message for a wrong password and for a damaged file: telling them
    // apart would tell an attacker holding the file whether a guess was close.
    /wrong secret or damaged vault/,
  );
});

test('a password wrapping cannot be passed off as a biometric one', async () => {
  const master = await deriveMasterKey('hunter2', newSalt(), FAST);
  const blob = await wrapVaultKey(newVaultKey(), master, 'password');
  // The label is authenticated, so relabelling the blob breaks it. Without
  // domain separation both wrappings are just "AES-GCM under some key" and one
  // can be offered where the other is expected.
  await assert.rejects(() => unwrapVaultKey({ ...blob, wrapper: 'biometric' }, master));
});

test('a record round-trips', async () => {
  const key = await importKey(newVaultKey());
  const plain = { title: 'BENCO', password: 'hunter2', urls: ['https://benco.example'] };
  const blob = await sealRecord(key, 'id-1', 7, plain);
  assert.deepEqual(await openRecord(key, 'id-1', 7, blob), plain);
});

test('a record sealed for one id will not open under another', async () => {
  const key = await importKey(newVaultKey());
  const blob = await sealRecord(key, 'id-1', 7, { password: 'a' });
  // This is the swap attack: a server hands back record B's ciphertext under
  // record A's identity. The AAD binding makes it fail to decrypt.
  await assert.rejects(() => openRecord(key, 'id-2', 7, blob), /failed to open/);
});

test('a record sealed at one revision will not open at another', async () => {
  const key = await importKey(newVaultKey());
  const blob = await sealRecord(key, 'id-1', 7, { password: 'current' });
  // The rollback attack: an old revision replayed as the current one, which
  // would resurrect a password already rotated away from.
  await assert.rejects(() => openRecord(key, 'id-1', 8, blob), /failed to open/);
});

test('a flipped bit in the ciphertext is detected', async () => {
  const key = await importKey(newVaultKey());
  const blob = await sealRecord(key, 'id-1', 1, { password: 'hunter2' });
  const ct = fromB64(blob.ct);
  ct[0] ^= 0x01;
  await assert.rejects(() => openRecord(key, 'id-1', 1, { ...blob, ct: toB64(ct) }));
});

test('every seal draws a fresh nonce', async () => {
  const key = await importKey(newVaultKey());
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    seen.add((await sealRecord(key, 'id-1', 1, { n: i })).n);
  }
  // GCM fails catastrophically rather than gracefully on key+nonce reuse, so a
  // counter or a cached nonce is the one bug worth an explicit test.
  assert.equal(seen.size, 200);
});

test('the vault key is imported non-extractable', async () => {
  const key = await importKey(newVaultKey());
  assert.equal(key.extractable, false);
  await assert.rejects(() => crypto.subtle.exportKey('raw', key));
});

test('hex helpers round-trip', () => {
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  assert.equal(toHex(fromHex(toHex(bytes))), toHex(bytes));
});
