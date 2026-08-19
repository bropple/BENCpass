import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Vault } from '../src/core/vault.js';
import { newRecoveryCode, normalise, ALPHABET, CODE_LENGTH, CODE_BITS } from '../src/core/recovery.js';

const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };
const mk = () => Vault.create({ password: 'hunter2', kdf: FAST });

// ---- the code itself --------------------------------------------------------

test('a code is unambiguous on paper', () => {
  // Somebody reads this off a printout years later, possibly in bad light.
  for (const ch of 'OIL01') assert.ok(!ALPHABET.includes(ch), `${ch} is confusable`);
  assert.ok(CODE_BITS >= 128, `only ${CODE_BITS} bits`);

  const code = newRecoveryCode();
  assert.equal(normalise(code).length, CODE_LENGTH);
  assert.match(code, /^[A-Z2-9]{5}(-[A-Z2-9]{5}){5}$/);
});

test('two codes are never the same', () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) seen.add(newRecoveryCode());
  assert.equal(seen.size, 500);
});

test('what was typed is reduced to what was meant', () => {
  const code = newRecoveryCode();
  // Lower case, line breaks, missing dashes, stray spaces: all presentation.
  assert.equal(normalise(code.toLowerCase()), normalise(code));
  assert.equal(normalise(code.replace(/-/g, '')), normalise(code));
  assert.equal(normalise(code.replace(/-/g, '\n  ')), normalise(code));
  // A misread character is dropped, never guessed at — there is no correct
  // substitution for a letter the alphabet does not contain.
  assert.equal(normalise('AAAA' + 'O'), 'AAAA');
});

// ---- the wrapping -----------------------------------------------------------

test('a recovery code opens the vault without the master password', async () => {
  const v = await mk();
  const id = await v.add({ title: 'Bank', password: 'hunter2' });

  const code = newRecoveryCode();
  await v.enrolRecovery('hunter2', code);
  assert.equal(v.hasRecovery, true);

  const reopened = Vault.load(v.toJSON());
  await reopened.unlockWithRecoveryCode(code);
  assert.equal(reopened.get(id).password, 'hunter2');
});

test('the master password still works afterwards, and so does the code', async () => {
  // Three independent wrappings of one key. None of them costs the others.
  const v = await mk();
  const code = newRecoveryCode();
  await v.enrolRecovery('hunter2', code);

  const byPassword = Vault.load(v.toJSON());
  await byPassword.unlock('hunter2');
  assert.equal(byPassword.locked, false);

  const byCode = Vault.load(v.toJSON());
  await byCode.unlockWithRecoveryCode(code);
  assert.equal(byCode.locked, false);
});

test('a wrong code is refused exactly as a wrong password is', async () => {
  const v = await mk();
  await v.enrolRecovery('hunter2', newRecoveryCode());

  const reopened = Vault.load(v.toJSON());
  await assert.rejects(
    () => reopened.unlockWithRecoveryCode(newRecoveryCode()),
    (err) => err.code === 'unwrap-failed',
  );
});

test('minting a way back in costs the master password', async () => {
  // Only somebody who can already open the vault can create a second way into
  // it. The key is a non-extractable CryptoKey once unlocked, so there is no
  // path to a wrapping except deriving it again.
  const v = await mk();
  await assert.rejects(() => v.enrolRecovery('wrong password', newRecoveryCode()));
  assert.equal(v.hasRecovery, false);
});

test('a half-typed code is refused before it is enrolled', async () => {
  const v = await mk();
  await assert.rejects(() => v.enrolRecovery('hunter2', 'ABCDE-FGHJK'), /full recovery code/);
});

test('the recovery wrapping has its own salt', async () => {
  // Sharing the password's salt would mean one Argon2 derivation served both,
  // so cracking either would be cracking both.
  const v = await mk();
  await v.enrolRecovery('hunter2', newRecoveryCode());
  assert.notEqual(v.toJSON().meta.wraps.recovery.salt, v.toJSON().meta.kdf.salt);
});

test('forgetting the recovery wrapping leaves the password alone', async () => {
  const v = await mk();
  const code = newRecoveryCode();
  await v.enrolRecovery('hunter2', code);
  v.forgetRecovery();
  assert.equal(v.hasRecovery, false);

  const reopened = Vault.load(v.toJSON());
  await reopened.unlock('hunter2');
  assert.equal(reopened.locked, false);
  await assert.rejects(() => Vault.load(v.toJSON()).unlockWithRecoveryCode(code), /no recovery wrapping/);
});

test('the wrappings are bound to their own names', async () => {
  // The recovery blob cannot be passed off as the password blob, and vice
  // versa: the AAD names which wrapping it is.
  const v = await mk();
  await v.enrolRecovery('hunter2', newRecoveryCode());
  const shipped = v.toJSON();
  shipped.meta.wraps.password = { ...shipped.meta.wraps.recovery, wrapper: 'password' };

  await assert.rejects(() => Vault.load(shipped).unlock('hunter2'));
});

test('minting a recovery wrap commits nothing until it is adopted', async () => {
  // The sheet shows the code before the vault commits to it. Enrolling first
  // and displaying second left a phantom: close the tab at the sheet and the
  // gate offers a recovery code that was never on anyone's screen. So minting
  // proves the password and builds the wrap, and only adopting makes it real.
  const v = await mk();
  const code = newRecoveryCode();

  const wrap = await v.mintRecoveryWrap('hunter2', code);
  assert.equal(v.hasRecovery, false, 'nothing may change before the code is acknowledged');

  // Bailing out here — the tab closed at the sheet — leaves a vault that
  // never heard of the code. That is the whole point.
  const bailed = Vault.load(v.toJSON());
  assert.equal(bailed.hasRecovery, false);
  await assert.rejects(() => bailed.unlockWithRecoveryCode(code));

  v.adoptRecoveryWrap(wrap);
  assert.equal(v.hasRecovery, true);
  const reopened = Vault.load(v.toJSON());
  await reopened.unlockWithRecoveryCode(code);
  assert.equal(reopened.locked, false);
});

test('minting still proves the master password before anything is shown', async () => {
  const v = await mk();
  await assert.rejects(() => v.mintRecoveryWrap('wrong password', newRecoveryCode()));
  assert.equal(v.hasRecovery, false);
});
