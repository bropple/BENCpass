import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Vault, VaultLockedError } from '../src/core/vault.js';
import { MemoryStorage } from '../src/core/storage.js';
import { deriveMasterKey, unwrapVaultKey } from '../src/core/crypto.js';
import { fromB64 } from '../src/core/bytes.js';

const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };
const mk = (password = 'hunter2') => Vault.create({ password, kdf: FAST });

const DAY = 86_400_000;
const T0 = 1_700_000_000_000;

test('a new vault is unlocked and empty', async () => {
  const v = await mk();
  assert.equal(v.locked, false);
  assert.deepEqual(v.list(), []);
});

test('a vault requires a master password to create', async () => {
  await assert.rejects(() => Vault.create({ password: '' }), /master password is required/);
});

test('records can be added and read back', async () => {
  const v = await mk();
  const id = await v.add({ title: 'BENCO', username: 'ben', password: 'hunter2' });
  assert.equal(v.get(id).title, 'BENCO');
  assert.equal(v.get(id).password, 'hunter2');
  assert.equal(v.get(id).rev, 1);
  assert.equal(v.list().length, 1);
});

test('a locked vault reveals nothing and accepts no writes', async () => {
  const v = await mk();
  await v.add({ title: 'BENCO', password: 'hunter2' });
  v.lock();

  assert.equal(v.locked, true);
  assert.throws(() => v.list(), VaultLockedError);
  assert.throws(() => v.get('anything'), VaultLockedError);
  await assert.rejects(() => v.add({ title: 'x' }), VaultLockedError);
});

test('a vault survives persist, load and unlock', async () => {
  const store = new MemoryStorage();
  const a = await mk();
  const id = await a.add({ title: 'BENCO', username: 'ben', password: 'hunter2' });
  await store.write(a.toJSON());

  const b = Vault.load(await store.read());
  assert.equal(b.locked, true);
  await b.unlock('hunter2');
  assert.equal(b.get(id).password, 'hunter2');
});

test('the wrong master password does not unlock', async () => {
  const v = Vault.load((await mk()).toJSON());
  await assert.rejects(() => v.unlock('hunter3'), /wrong secret or damaged vault/);
  assert.equal(v.locked, true);
});

test('nothing readable is written to storage', async () => {
  const v = await mk();
  await v.add({ title: 'BENCO', username: 'ben', password: 'swordfish' });
  const serialised = JSON.stringify(v.toJSON());
  for (const secret of ['BENCO', 'ben', 'swordfish']) {
    assert.equal(serialised.includes(secret), false, `${secret} leaked into storage`);
  }
});

test('an unsupported format is refused rather than guessed at', async () => {
  const bad = (await mk()).toJSON();
  bad.meta.format = 99;
  assert.throws(() => Vault.load(bad), /unsupported vault format/);
});

test('the biometric path reaches the same vault key', async () => {
  const a = await mk();
  const id = await a.add({ title: 'BENCO', password: 'hunter2' });

  // Stand in for the native host: recover the vault key the way the host would
  // have had it at enrolment, then unlock with it directly.
  const master = await deriveMasterKey('hunter2', fromB64(a.meta.kdf.salt), a.meta.kdf);
  const vaultKey = await unwrapVaultKey(a.meta.wraps.password, master);

  const b = Vault.load(a.toJSON());
  await b.unlockWithVaultKey(vaultKey);
  assert.equal(b.get(id).password, 'hunter2');
});

test('an update bumps the revision and re-seals', async () => {
  const v = await mk();
  const id = await v.add({ title: 'BENCO', password: 'hunter2' });
  const before = { ...v.envelopes.get(id) };

  await v.update(id, { title: 'BENCO Holdings' });

  const after = v.envelopes.get(id);
  assert.equal(after.rev, before.rev + 1);
  // Re-sealed, not merely relabelled — the AAD binds the revision, so carrying
  // the old ciphertext forward would fail to open.
  assert.notEqual(after.ct, before.ct);
  assert.equal(v.get(id).title, 'BENCO Holdings');
});

test('changing the password records the old one and stamps passwordChanged', async () => {
  const v = await mk();
  const id = await v.add({ title: 'BENCO', password: 'hunter2' }, T0);
  await v.update(id, { password: 'swordfish' }, T0 + DAY);

  const r = v.get(id);
  assert.equal(r.password, 'swordfish');
  assert.equal(r.passwordChanged, T0 + DAY);
  assert.deepEqual(r.history, [{ password: 'hunter2', changed: T0 }]);
});

test('editing anything else leaves passwordChanged alone', async () => {
  const v = await mk();
  const id = await v.add({ title: 'BENCO', password: 'hunter2' }, T0);
  await v.update(id, { notes: 'the one with the pentagon' }, T0 + 400 * DAY);

  const r = v.get(id);
  // If a rename reset this, every age audit would report the vault as healthy
  // the moment anyone tidied it up.
  assert.equal(r.passwordChanged, T0);
  assert.equal(r.updated, T0 + 400 * DAY);
  assert.deepEqual(r.history, []);
});

test('password history is capped', async () => {
  const v = await mk();
  const id = await v.add({ title: 'BENCO', password: 'p0' }, T0);
  for (let i = 1; i <= 25; i++) await v.update(id, { password: `p${i}` }, T0 + i * DAY);

  const r = v.get(id);
  assert.equal(r.history.length, 20);
  assert.equal(r.history[0].password, 'p24'); // most recent first
});

test('a fill is recorded without counting as an edit', async () => {
  const v = await mk();
  const id = await v.add({ title: 'BENCO', password: 'hunter2' }, T0);
  await v.touchUsed(id, T0 + DAY);

  const r = v.get(id);
  assert.equal(r.timesUsed, 1);
  assert.equal(r.lastUsed, T0 + DAY);
  assert.equal(r.passwordChanged, T0);
  assert.deepEqual(r.history, []);
});

test('a removal leaves an authenticated tombstone, not a hole', async () => {
  const v = await mk();
  const id = await v.add({ title: 'BENCO', password: 'hunter2' });
  await v.remove(id);

  assert.equal(v.get(id), undefined);
  assert.equal(v.list().length, 0);

  const env = v.envelopes.get(id);
  assert.equal(env.deleted, true);
  assert.equal(env.rev, 2);
  // Sealed, so the server cannot invent one. A bare flag would be forgeable.
  assert.ok(env.ct);
});

test('a tombstoned record stays absent across a reload', async () => {
  const a = await mk();
  const id = await a.add({ title: 'BENCO', password: 'hunter2' });
  await a.remove(id);

  const b = Vault.load(a.toJSON());
  await b.unlock('hunter2');
  assert.equal(b.get(id), undefined);
});

test('import normalises timestamps and clamps ones from the future', async () => {
  const v = await mk();
  const [ok, future, bare] = await v.importRecords(
    [
      { title: 'sane', password: 'a', created: T0, passwordChanged: T0 + DAY },
      { title: 'bad clock', password: 'b', created: T0 + 900 * DAY },
      { title: 'no timestamps at all', password: 'c' },
    ],
    T0 + 10 * DAY,
  );

  assert.equal(v.get(ok).created, T0);
  assert.equal(v.get(ok).passwordChanged, T0 + DAY);

  // Clamped to now, with what the file claimed kept for the UI to explain.
  assert.equal(v.get(future).created, T0 + 10 * DAY);
  assert.equal(v.get(future).claimedTime, T0 + 900 * DAY);

  assert.equal(v.get(bare).created, T0 + 10 * DAY);
  assert.equal(v.get(bare).timesUsed, 0);
  assert.deepEqual(v.get(bare).urls, []);
});

test('export returns everything import took', async () => {
  const v = await mk();
  await v.importRecords([
    { title: 'one', username: 'a', password: 'p1' },
    { title: 'two', username: 'b', password: 'p2' },
  ]);
  const out = v.exportPlain();
  assert.equal(out.length, 2);
  assert.deepEqual(out.map((r) => r.password).sort(), ['p1', 'p2']);
});

test('search covers the fields someone would actually type', async () => {
  const v = await mk();
  await v.add({ title: 'BENCO Holdings', username: 'ben', urls: ['https://benco.example'] });
  await v.add({ title: 'Something else', username: 'other', notes: 'pentagon' });

  assert.equal(v.search('benco').length, 1); // matches on title and on url
  assert.equal(v.search('example').length, 1); // url alone
  assert.equal(v.search('PENTAGON').length, 1); // case-insensitive, notes
  assert.equal(v.search('   ').length, 2); // blank falls back to everything
  assert.equal(v.search('nothing here').length, 0);
});

// ---- addresses -------------------------------------------------------------

test('an address is stored in the same vault as a login', async () => {
  const v = await mk();
  const login = await v.add({ title: 'BENCO', password: 'hunter2' });
  const addr = await v.add({
    type: 'address',
    title: 'Home',
    name: 'Ben',
    'address-line1': '1 Pentagon Way',
    'address-level2': 'Springfield',
    'postal-code': 'SW1A 1AA',
    country: 'GB',
  });

  assert.equal(v.get(login).type, 'login');
  assert.equal(v.get(addr).type, 'address');
  assert.equal(v.get(addr)['address-line1'], '1 Pentagon Way');
  assert.equal(v.list().length, 2);
  assert.equal(v.list('address').length, 1);
  assert.equal(v.list('login').length, 1);
});

test('an address has no password, no history and no age', async () => {
  const v = await mk();
  const id = await v.add({ type: 'address', title: 'Home', name: 'Ben' }, T0);
  await v.update(id, { name: 'Ben R', password: 'sneaked in' }, T0 + DAY);

  const r = v.get(id);
  assert.equal(r.name, 'Ben R');
  // Guarding on the type keeps a stray key in a patch from growing a history
  // and an age on a record that should have neither.
  assert.equal(r.history, undefined);
  assert.equal(r.passwordChanged, undefined);
  assert.equal(r.updated, T0 + DAY);
});

test('an unknown record type is refused', async () => {
  const v = await mk();
  await assert.rejects(() => v.add({ type: 'creditcard', title: 'no' }), /unknown record type/);
});

test('addresses survive a lock and unlock like anything else', async () => {
  const a = await mk();
  const id = await a.add({ type: 'address', title: 'Work', 'postal-code': 'EC1A 1BB' });

  const b = Vault.load(a.toJSON());
  await b.unlock('hunter2');
  assert.equal(b.get(id)['postal-code'], 'EC1A 1BB');
  assert.equal(b.get(id).type, 'address');
});

test('search reaches address fields, and can be limited by type', async () => {
  const v = await mk();
  await v.add({ title: 'BENCO', username: 'ben', urls: ['https://springfield.example'] });
  await v.add({
    type: 'address',
    title: 'Home',
    'address-line1': '1 Pentagon Way',
    'address-level2': 'Springfield',
  });

  assert.equal(v.search('pentagon').length, 1);
  assert.equal(v.search('springfield').length, 2); // a url and a city
  assert.equal(v.search('springfield', 'address').length, 1);
  assert.equal(v.search('', 'address').length, 1);
});
