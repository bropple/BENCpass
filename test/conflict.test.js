// The conflict machinery: parked envelopes that survive, forks a person can
// see, and revisions that only move forward.
//
// The scenario that forced all of this into existence is the first test: a
// genuine tombstone, sealed by a machine that shares this vault's history,
// arriving with a revision above the acknowledged base but below the local
// edit. merge() resolves it in the tombstone's favour — deliberately, so a
// deletion is not undone by an edit racing it — and before the park was real,
// that resolution silently and permanently deleted the live password. Nothing
// refused it, nothing kept the losing copy, and the manager said "kept" about
// a keep that never happened.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Vault } from '../src/core/vault.js';
import { merge, CONFLICT } from '../src/core/merge.js';

const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };
const mk = (password = 'hunter2') => Vault.create({ password, kdf: FAST });

/** A second machine sharing this vault's key and history. */
async function twin(vault, password = 'hunter2') {
  const other = Vault.load(vault.toJSON());
  await other.unlock(password);
  return other;
}

test('a stale but authentic tombstone no longer deletes a password beyond recovery', async () => {
  const a = await mk();
  const id = await a.add({ title: 'Shared', password: 'original' }); // rev 1
  await a.update(id, { password: 'second' }); // rev 2 — the acknowledged base

  // The other machine deletes at rev 3; this one goes on editing to rev 4.
  const b = await twin(a);
  await b.remove(id); // tombstone, rev 3
  await a.update(id, { password: 'almost' }); // rev 3
  await a.update(id, { password: 'CURRENT' }); // rev 4

  const result = merge({
    local: a.envelopes,
    remote: [b.envelopes.get(id)],
    syncedRev: { [id]: 2 },
  });

  // The shape of the trap, pinned: the rollback guard does not fire (rev 3 is
  // above the base of 2), the tombstone wins, and the record is gone.
  assert.equal(result.actions.get(id), CONFLICT);
  assert.equal(result.conflicts[0].kind, 'delete');
  assert.deepEqual(result.rolledBack, []);
  await a.applyEnvelopes(result.envelopes);
  assert.equal(a.get(id), undefined);

  // What used to be the end of the story. Now the losing edit is parked, the
  // park survives storage, and the next unlock forks it into a record.
  a.park(result.conflicts.map((c) => c.parked));
  const reloaded = Vault.load(a.toJSON());
  assert.equal(reloaded.parked.length, 1, 'the parked copy must survive persist and load');

  await reloaded.unlock('hunter2');
  const forked = await reloaded.resolveParked();
  assert.equal(forked.length, 1);

  const copy = reloaded.get(forked[0]);
  assert.equal(copy.password, 'CURRENT');
  assert.match(copy.title, /\(conflict\)$/);
  assert.equal(copy.conflictOf, id);
  assert.match(copy.notes, /sync conflict/);
});

test('parking needs no key, which is what saves the locked background sync', async () => {
  const a = await mk();
  const id = await a.add({ title: 'Shared', password: 'CURRENT' });

  const b = await twin(a);
  await b.remove(id);

  // The vault the background syncs with is locked. The tombstone is adopted —
  // its rev is not lower, and the flag says tombstone — and the losing side is
  // parked without ever touching the key.
  const locked = Vault.load(a.toJSON());
  assert.equal(locked.locked, true);

  const result = merge({
    local: locked.envelopes,
    remote: [b.envelopes.get(id)],
    syncedRev: {},
  });
  await locked.applyEnvelopes(result.envelopes);
  assert.equal(locked.park(result.conflicts.map((c) => c.parked)), 1);

  await locked.unlock('hunter2');
  assert.equal(locked.get(id), undefined, 'the deletion is honoured');

  const forked = await locked.resolveParked();
  assert.equal(locked.get(forked[0]).password, 'CURRENT', 'but the password is not gone');
});

test('the same conflict re-detected does not park or fork the same bytes twice', async () => {
  const a = await mk();
  const id = await a.add({ title: 'Shared', password: 'mine' });
  const b = await twin(a);
  await b.update(id, { password: 'theirs' });
  const parked = b.envelopes.get(id);

  // Every sync until convergence re-detects the conflict and re-parks the
  // same envelope. Once parked, and again once forked, it is a no-op.
  assert.equal(a.park([parked]), 1);
  assert.equal(a.park([parked]), 0);

  assert.equal((await a.resolveParked()).length, 1);
  assert.equal(a.park([parked]), 0, 'a forked envelope must not come back');
  assert.deepEqual(await a.resolveParked(), []);
});

test('a parked copy that only differs in use-counts is not worth a fork', async () => {
  const a = await mk();
  const id = await a.add({ title: 'Shared', username: 'ben', password: 'same' });

  // The other machine merely used the record: fresh bytes, same content.
  const b = await twin(a);
  await b.touchUsed(id);

  a.park([b.envelopes.get(id)]);
  assert.deepEqual(await a.resolveParked(), [], 'forking this would just manufacture a duplicate');
});

test('a parked tombstone is dropped, not forked — there is nothing in it to recover', async () => {
  const a = await mk();
  const id = await a.add({ title: 'Doomed', password: 'x' });
  const b = await twin(a);
  await b.remove(id);

  a.park([b.envelopes.get(id)]);
  assert.deepEqual(await a.resolveParked(), []);
  assert.equal(a.parked.length, 0);
});

test('supersede re-seals the same content strictly above both sides', async () => {
  const a = await mk();
  const id = await a.add({ title: 'Shared', password: 'mine' }); // rev 1

  const rev = await a.supersede(id, 4); // the remote reached 4
  assert.equal(rev, 5);
  assert.equal(a.envelopes.get(id).rev, 5);

  // The bytes still open under the AAD that binds id and rev — a locked round
  // trip proves the seal is real rather than a renumbered envelope.
  const reloaded = Vault.load(a.toJSON());
  await reloaded.unlock('hunter2');
  assert.equal(reloaded.get(id).password, 'mine');
});

test('supersede works on a tombstone, so a winning deletion can break a tie too', async () => {
  const a = await mk();
  const id = await a.add({ title: 'Doomed', password: 'x' }); // rev 1
  await a.remove(id); // rev 2, tombstone

  const rev = await a.supersede(id, 2);
  assert.equal(rev, 3);
  assert.equal(a.envelopes.get(id).deleted, true);

  // Still a deletion after a round trip: the re-sealed body says so.
  const reloaded = Vault.load(a.toJSON());
  await reloaded.unlock('hunter2');
  assert.equal(reloaded.get(id), undefined);
});

test('a locked vault refuses a live envelope going backwards', async () => {
  const a = await mk();
  const id = await a.add({ title: 'Rotated', password: 'old' }); // rev 1
  const stale = a.envelopes.get(id); // the pre-rotation envelope, genuinely sealed
  await a.update(id, { password: 'new' }); // rev 2

  // The background sync runs on a locked vault, and the revision comparison
  // used to live only on the unlocked path — so the one sync that runs
  // unattended was the one with no belt at all.
  const locked = Vault.load(a.toJSON());
  assert.equal(locked.locked, true);
  await locked.applyEnvelopes([stale]);
  assert.equal(locked.envelopes.get(id).rev, 2, 'the newer envelope must survive');

  await locked.unlock('hunter2');
  assert.equal(locked.get(id).password, 'new');
});

test('a conflict copy keeps its own date, so the two can be told apart', async () => {
  // The one question a person has when two copies of a login appear is which
  // one they wrote last. Stamping the fork with the moment it was forked makes
  // both copies claim the same date and leaves them choosing blind.
  const early = Date.parse('2026-01-10T00:00:00Z');
  const late = Date.parse('2026-06-20T00:00:00Z');
  const forkedAt = Date.parse('2026-08-19T00:00:00Z');

  const v = await Vault.create({ password: 'pw', now: early });
  const id = await v.add(
    { type: 'login', title: 'Bank', username: 'ben', password: 'from-the-laptop' },
    early,
  );

  // The other machine's copy, written months later than this one.
  const other = Vault.load(JSON.parse(JSON.stringify(v.toJSON())));
  await other.unlock('pw');
  await other.update(id, { password: 'from-the-desktop' }, late);
  const losing = JSON.parse(JSON.stringify(other.toJSON().envelopes.find((e) => e.id === id)));

  await v.park([losing]);
  const forked = await v.resolveParked(forkedAt);
  assert.equal(forked.length, 1);

  const copy = v.get(forked[0]);
  assert.equal(copy.password, 'from-the-desktop');
  assert.equal(
    copy.updated,
    late,
    'the conflict copy was stamped with the fork time, losing the date it was actually written',
  );
  assert.ok(copy.notes.includes('2026-06-20'), 'the note should say when this copy was written');
  assert.ok(copy.notes.includes('2026-08-19'), 'and when the conflict was found');
});
