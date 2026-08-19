import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Vault, VaultLockedError } from '../src/core/vault.js';
import { MemoryStorage } from '../src/core/storage.js';
import { deriveMasterKey, unwrapVaultKey, randomBytes } from '../src/core/crypto.js';
import { fromB64, toB64 } from '../src/core/bytes.js';

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

test('the retired format 1 is refused by name, never opened', async () => {
  // Format 1 left the `deleted` flag outside the AAD, so a reader that still
  // accepted it would be a downgrade path: relabel an envelope as format 1 and
  // the flippable flag is back. Nobody is stranded by the refusal — v0.11.0
  // wrote format 1 but was never run — so a stray test vault gets told what it
  // is, plainly, instead of being opened under weaker rules.
  const bad = (await mk()).toJSON();
  bad.meta.format = 1;
  assert.throws(() => Vault.load(bad), /older BENCpass/);
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

// ---- the second wrapping ----------------------------------------------------
//
// One vault key, two independent wrappings: the master password, and a random
// device secret an operating system holds behind a fingerprint. The tests that
// matter are the ones about independence — that neither wrapping weakens the
// other, and that dropping one is a local act.

test('a device secret opens the same vault as the password', async () => {
  const v = await Vault.create({ password: 'correct horse battery staple' });
  const id = await v.add({ title: 'Router', username: 'admin', password: 'hunter2' });

  const secret = randomBytes(32);
  await v.enrolBiometric('correct horse battery staple', secret);

  const reopened = Vault.load(JSON.parse(JSON.stringify(v.toJSON())));
  assert.equal(reopened.locked, true);
  await reopened.unlockWithBiometricSecret(secret);
  assert.equal(reopened.get(id).password, 'hunter2');
});

test('the password still works after enrolling, and vice versa', async () => {
  const v = await Vault.create({ password: 'pw' });
  await v.add({ title: 'x', password: 'secret' });
  const secret = randomBytes(32);
  await v.enrolBiometric('pw', secret);

  const json = JSON.parse(JSON.stringify(v.toJSON()));
  const byPassword = Vault.load(json);
  await byPassword.unlock('pw');
  assert.equal(byPassword.list()[0].password, 'secret');

  const bySecret = Vault.load(json);
  await bySecret.unlockWithBiometricSecret(secret);
  assert.equal(bySecret.list()[0].password, 'secret');
});

test('enrolling needs the real master password', async () => {
  const v = await Vault.create({ password: 'pw' });
  await assert.rejects(() => v.enrolBiometric('not the password', randomBytes(32)), {
    code: 'unwrap-failed',
  });
  assert.equal(v.hasBiometric, false);
});

test('a wrong device secret is refused exactly as a wrong password is', async () => {
  const v = await Vault.create({ password: 'pw' });
  await v.enrolBiometric('pw', randomBytes(32));
  const reopened = Vault.load(JSON.parse(JSON.stringify(v.toJSON())));
  await assert.rejects(() => reopened.unlockWithBiometricSecret(randomBytes(32)), {
    code: 'unwrap-failed',
  });
});

test('the device secret has to be a full-length key', async () => {
  const v = await Vault.create({ password: 'pw' });
  await assert.rejects(() => v.enrolBiometric('pw', randomBytes(16)), /32 bytes/);
  await assert.rejects(() => v.enrolBiometric('pw', undefined), /32 bytes/);
});

test('forgetting is local: the password wrapping is untouched', async () => {
  const v = await Vault.create({ password: 'pw' });
  await v.add({ title: 'x', password: 'secret' });
  const secret = randomBytes(32);
  await v.enrolBiometric('pw', secret);
  assert.equal(v.hasBiometric, true);

  v.forgetBiometric();
  assert.equal(v.hasBiometric, false);

  const reopened = Vault.load(JSON.parse(JSON.stringify(v.toJSON())));
  await reopened.unlock('pw');
  assert.equal(reopened.list()[0].password, 'secret');
  // And the secret is now useless, which is what makes forgetting cheap.
  await assert.rejects(
    () => Vault.load(JSON.parse(JSON.stringify(v.toJSON()))).unlockWithBiometricSecret(secret),
    /no biometric wrapping/,
  );
});

test('a vault with no second wrapping says so rather than guessing', async () => {
  const v = await Vault.create({ password: 'pw' });
  assert.equal(v.hasBiometric, false);
  await assert.rejects(() => v.unlockWithBiometricSecret(randomBytes(32)), /no biometric wrapping/);
});

test('the two wrappings are bound to their own names', async () => {
  // The AAD carries the wrapper name, so a blob moved from one slot to the
  // other fails to decrypt. Without that a server or a tampered file could
  // present the password wrapping as the biometric one.
  const v = await Vault.create({ password: 'pw' });
  await v.enrolBiometric('pw', randomBytes(32));

  const json = JSON.parse(JSON.stringify(v.toJSON()));
  json.meta.wraps.biometric = { ...json.meta.wraps.password, wrapper: 'biometric' };
  const tampered = Vault.load(json);
  await assert.rejects(() => tampered.unlockWithBiometricSecret(randomBytes(32)), {
    code: 'unwrap-failed',
  });
});

test('a secret that travelled as base64 through a message still enrols', async () => {
  // The path the extension actually takes: derived in a document, encoded,
  // posted to the background, decoded there. The bytes are the same bytes, but
  // the tests had only ever handed enrolBiometric a fresh Uint8Array.
  const v = await Vault.create({ password: 'pw' });
  await v.add({ title: 'x', password: 'secret' });

  const derived = randomBytes(32);
  const encoded = Buffer.from(derived).toString('base64');
  const received = Uint8Array.from(Buffer.from(encoded, 'base64'));

  await v.enrolBiometric('pw', received);
  const reopened = Vault.load(JSON.parse(JSON.stringify(v.toJSON())));
  await reopened.unlockWithBiometricSecret(received);
  assert.equal(reopened.list()[0].password, 'secret');
});

// ---- the `deleted` flag is not the server's to set ---------------------------
//
// It sits beside the ciphertext in the clear, but the AAD covers it, so anyone
// who flips it — the server, or anyone who can write the vault file — breaks
// the seal rather than changing what a reader believes. These two tests
// predate the binding, and their meaning has shifted underneath them: they
// used to pin that readers consulted the sealed body instead of the flag; now
// they pin that a one-bit lie in the local file is survived rather than turned
// into a lockout. The vault re-opens the envelope under the only other claim
// it could have made — both attempts authenticate the full AAD, so what comes
// back is the sealer's word, not the tamperer's — and the record neither
// vanishes nor resurrects.

test('a record flipped to deleted in the file does not vanish', async () => {
  const v = await Vault.create({ password: 'hunter2', kdf: FAST });
  const id = await v.add({ title: 'Bank', password: 'hunter2' });

  const shipped = v.toJSON();
  // Exactly what a hostile server or a profile thief can do: set the flag,
  // leave the ciphertext untouched. No key needed.
  shipped.envelopes.find((e) => e.id === id).deleted = true;

  const reopened = Vault.load(shipped);
  await reopened.unlock('hunter2');

  assert.equal(reopened.list().length, 1, 'a record was suppressed by a flag nobody signed');
  assert.equal(reopened.get(id).title, 'Bank');
});

test('the flipped-flag recovery cannot be used to hide real damage', async () => {
  // The unlock retries a failed envelope under the inverted flag, and only
  // there. If it treated every failure as a flipped flag it would loop; if it
  // swallowed the second failure it would silently drop a corrupted record —
  // the failure mode openRecord's loud error exists to prevent. A ciphertext
  // bit-flip must therefore still fail the unlock, with the original error.
  const v = await Vault.create({ password: 'hunter2', kdf: FAST });
  const id = await v.add({ title: 'Bank', password: 'hunter2' });

  const shipped = v.toJSON();
  const env = shipped.envelopes.find((e) => e.id === id);
  const ct = fromB64(env.ct);
  ct[0] ^= 0x01;
  env.ct = toB64(ct);

  // The vault still opens — one fabricated envelope adopted by a keyless
  // locked sync used to shut it for ever, with the correct master password —
  // but the record is named rather than quietly missing. Silence here would
  // be the failure openRecord's loud error exists to prevent; a lockout was
  // the worse one.
  const reopened = Vault.load(shipped);
  await reopened.unlock('hunter2');
  assert.deepEqual(reopened.damaged, [id], 'the corrupted record was dropped without saying so');
  assert.equal(reopened.get(id), undefined);
});

test('a tombstone flipped to live stays deleted', async () => {
  const v = await Vault.create({ password: 'hunter2', kdf: FAST });
  const id = await v.add({ title: 'Gone', password: 'x' });
  await v.remove(id);

  const shipped = v.toJSON();
  // The other direction: clear the flag and try to resurrect the record. What
  // surfaces would otherwise be the tombstone body itself.
  shipped.envelopes.find((e) => e.id === id).deleted = false;

  const reopened = Vault.load(shipped);
  await reopened.unlock('hunter2');

  assert.equal(reopened.list().length, 0, 'a deleted record came back');
});

// Two vaults on one key, the way two enrolled machines share one vault.
async function pair() {
  const a = await Vault.create({ password: 'hunter2', kdf: FAST });
  const meta = a.toJSON().meta;
  const master = await deriveMasterKey('hunter2', fromB64(meta.kdf.salt), meta.kdf);
  const vaultKey = await unwrapVaultKey(meta.wraps.password, master);
  const b = Vault.load({ meta: structuredClone(meta), envelopes: [], syncedRev: {} });
  await b.unlockWithVaultKey(vaultKey);
  return [a, b];
}

test('a flag flipped to deleted on a NEWER live envelope cannot cross a tombstone, even via a locked sync', async () => {
  // The one flag-flip with teeth. merge, key-free, lets a claimed tombstone
  // fast-forward over a local tombstone — that is how two machines deleting
  // the same record settle — so a server can dress another machine's live
  // edit as a deletion to get it past ours. A LOCKED sync cannot open the
  // body to notice; it must therefore remember that this envelope crossed a
  // tombstone on the flag's word, and the unlock, which can open it, must
  // honour the deletion and hand the smuggled body to a person instead.
  const [a, b] = await pair();
  const id = await a.add({ title: 'Bank', password: 'pw1' });
  await b.applyEnvelopes(new Map(a.envelopes));
  await b.update(id, { password: 'pw3' }); // rev 2, live, authentic
  await a.remove(id); // rev 2, tombstone

  const flipped = { ...b.envelopes.get(id), rev: 3, deleted: true };
  // Re-seal at rev 3 the honest way (the server can only replay authentic
  // bytes at their own rev, but a rev-3 edit is authentic too).
  await b.update(id, { password: 'pw3' });
  flipped.ct = b.envelopes.get(id).ct;
  flipped.n = b.envelopes.get(id).n;

  a.lock();
  await a.applyEnvelopes(new Map([[id, flipped]])); // locked: adopts on the flag's word
  const master = await deriveMasterKey('hunter2', fromB64(a.meta.kdf.salt), a.meta.kdf);
  await a.unlockWithVaultKey(await unwrapVaultKey(a.meta.wraps.password, master));

  assert.equal(a.get(id), undefined, 'a deleted record was resurrected by a flipped flag');
  const forked = await a.resolveParked();
  assert.equal(forked.length, 1, 'the smuggled live body was dropped instead of parked');
  assert.match(a.get(forked[0]).title, /\(conflict\)/);
  assert.equal(a.get(forked[0]).password, 'pw3', 'the parked body must be the smuggled edit');
});

test('an unlocked apply refuses an incoming envelope whose flag contradicts its body', async () => {
  const [a, b] = await pair();
  const id = await a.add({ title: 'Bank', password: 'pw1' });
  await b.applyEnvelopes(new Map(a.envelopes));
  await b.update(id, { password: 'pw2' }); // rev 2, live

  const flipped = { ...b.envelopes.get(id), deleted: true };
  await assert.rejects(
    () => a.applyEnvelopes(new Map([[id, flipped]])),
    (err) => err.code === 'tampered',
    'a flag contradicting the sealed body must be refused, not adopted',
  );
  assert.equal(a.get(id).password, 'pw1', 'the refused envelope must change nothing');
});

test('a record cannot seal its own disappearance', async () => {
  // `deleted` in a sealed body is what a reader takes as proof a record was
  // removed. A record carrying it would vanish at the next unlock with its
  // ciphertext intact and nothing to point at — so it never survives into one.
  const v = await Vault.create({ password: 'hunter2', kdf: FAST });
  const id = await v.add({ title: 'Still here', password: 'x', deleted: true });

  assert.equal(v.get(id).deleted, undefined, 'a record kept a tombstone marker');

  const reopened = Vault.load(v.toJSON());
  await reopened.unlock('hunter2');
  assert.equal(reopened.list().length, 1, 'a record sealed its own disappearance');
  assert.equal(reopened.get(id).title, 'Still here');
});

test('an imported record cannot seal its own disappearance either', async () => {
  // The same guard as above, through the other door. `normalise` is what
  // importRecords runs, and reverting the guard there broke no test at all —
  // the record stayed visible until the vault was reopened and was gone
  // afterwards, with its ciphertext intact.
  const v = await Vault.create({ password: 'hunter2', kdf: FAST });
  await v.importRecords([{ type: 'login', title: 'Imported', password: 'p', deleted: true }]);

  const reopened = Vault.load(v.toJSON());
  await reopened.unlock('hunter2');
  assert.equal(reopened.list().length, 1, 'an imported record sealed its own disappearance');
  assert.equal(reopened.list()[0].title, 'Imported');
});

test('an encrypted backup cannot be opened by a fingerprint', async () => {
  // The interface calls this file safe to keep anywhere, and names the two
  // things that open it: the master password and the recovery code. The
  // fingerprint wrapping would have been a third, and a quieter one — the
  // secret behind it is a PRF output the authenticator hands to whoever
  // presents the credential, which for a syncing passkey can be another of the
  // account's devices. Nothing outside a browser can use it in any case.
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const v = await Vault.create({ password: 'pw' });
  await v.add({ type: 'login', title: 'bank', username: 'u', password: 'secret' });
  await v.enrolBiometric('pw', secret);
  assert.ok(v.hasBiometric, 'the vault under test must have a fingerprint enrolled');

  const backup = JSON.parse(JSON.stringify(v.backup()));
  assert.equal(backup.meta.wraps.biometric, null, 'the fingerprint wrapping is in the backup');

  const stolen = Vault.load(backup);
  await assert.rejects(
    () => stolen.unlockWithBiometricSecret(secret),
    'the device secret alone opened a backup',
  );

  // Still the file it claims to be: the password opens it, whole.
  const mine = Vault.load(backup);
  await mine.unlock('pw');
  assert.equal(mine.list()[0].password, 'secret');

  // And taking a backup did not cost the live vault its fingerprint. toJSON
  // hands back meta itself, so blanking the wrap in place would have.
  assert.ok(v.hasBiometric, 'taking a backup removed the live vault\'s fingerprint');
  await v.unlockWithBiometricSecret(secret);
});

test('an encrypted backup is exactly what a second implementation needs', async () => {
  // What Settings -> Your data -> Encrypted backup writes, and what
  // rescue/internal/vault reads. The two are a format apart and cannot import
  // each other, so the shape is pinned here: a backup carries the header and
  // the sealed records, and nothing that only means something on one machine.
  const v = await Vault.create({ password: 'pw' });
  await v.add({ type: 'login', title: 'a', username: 'u', password: 'p' });

  const backup = JSON.parse(JSON.stringify(v.backup()));

  assert.deepEqual(Object.keys(backup).sort(), ['envelopes', 'meta']);
  assert.equal(backup.syncedRev, undefined);
  assert.ok(backup.meta.kdf.salt, 'the header must carry the salt');
  assert.ok(backup.meta.wraps.password, 'the header must carry the password wrapping');

  // And it still opens, which is the whole point of keeping one.
  const back = Vault.load(backup);
  await back.unlock('pw');
  assert.equal(back.list().length, 1);
  assert.equal(back.list()[0].password, 'p');
});

test('a live record cannot be rolled back through applyEnvelopes', async () => {
  // Belt and braces beneath merge(). The envelope an attacker replays opens
  // perfectly — it was genuinely sealed at that revision, so its AAD verifies —
  // which is why the revision has to be checked here rather than left to the
  // cryptography to catch.
  const v = await Vault.create({ password: 'pw' });
  const id = await v.add({ type: 'login', title: 'Bank', username: 'ben', password: 'LEAKED' });
  const old = JSON.parse(JSON.stringify(v.toJSON().envelopes.find((e) => e.id === id)));

  await v.update(id, { password: 'ROTATED' });
  assert.equal(v.get(id).password, 'ROTATED');

  await v.applyEnvelopes([old]);
  assert.equal(v.get(id).password, 'ROTATED', 'a replayed envelope rolled the password back');
  assert.equal(v.envelopes.get(id).rev, 2, 'the stored envelope regressed');
});

test('a tombstone may still arrive below the local revision', async () => {
  // The case that makes the rule above "no regression for a LIVE record"
  // rather than "no regression". A deletion on one machine racing edits on
  // another is resolved by merge in the tombstone's favour, and that tombstone
  // is legitimately a lower revision than the local edit. Refusing every
  // regression would quietly break deleting a record, which is the fail-safe
  // direction and must keep working.
  const v = await Vault.create({ password: 'pw' });
  const id = await v.add({ type: 'login', title: 'Gone', username: 'x', password: 'p' });

  // The other machine deletes from rev 1, sealing a tombstone at rev 2. Sealed
  // there for real — rewriting `rev` on an envelope after the fact only breaks
  // the AAD it was sealed under, which is how the first version of this test
  // managed to fail against correct code.
  const other = Vault.load(JSON.parse(JSON.stringify(v.toJSON())));
  await other.unlock('pw');
  await other.remove(id);
  const tomb = JSON.parse(JSON.stringify(other.toJSON().envelopes.find((e) => e.id === id)));
  assert.equal(tomb.rev, 2);

  // Meanwhile this machine edits twice and is ahead.
  await v.update(id, { password: 'p2' });
  await v.update(id, { password: 'p3' });
  assert.equal(v.envelopes.get(id).rev, 3);

  await v.applyEnvelopes([tomb]);
  assert.equal(v.list().length, 0, 'a deletion was refused because its revision was lower');
});

test('a mark only this machine can make cannot arrive from a server', async () => {
  // `overTombstone` says "a locked sync here adopted this on the flag's word",
  // and everything downstream treats it as proof the mark was made locally. It
  // is a cleartext field, so a server could write it and be believed: enough
  // to have a live record hidden as a tombstone and re-minted under a new id
  // as a visible "(conflict)" fork, pushed to every machine.
  const { fromWire } = await import('../src/core/sync.js');
  const hostile = [
    { id: 'a', rev: 2, deleted: true, n: 'n', ct: 'c', overTombstone: true, seq: 9, extra: 'x' },
  ];
  const [clean] = fromWire(hostile);
  assert.equal(clean.overTombstone, undefined, 'a server-supplied local mark survived');
  assert.equal(clean.extra, undefined);
  assert.equal(clean.seq, undefined);
  assert.deepEqual(Object.keys(clean).sort(), ['ct', 'deleted', 'id', 'n', 'rev']);
});
