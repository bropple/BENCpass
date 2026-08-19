import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  merge,
  confirmPushed,
  FAST_FORWARD,
  KEEP_LOCAL,
  ACCEPT_NEW,
  IN_SYNC,
  CONFLICT,
  ROLLBACK,
} from '../src/core/merge.js';

// Envelopes only. The merge never sees plaintext, which is the point: it cannot
// reach a timestamp even if it wanted one, so its ordering is causal rather
// than chronological and holds under any amount of clock skew.
const env = (id, rev, deleted = false) => ({ id, rev, deleted, n: 'n', ct: `ct${rev}` });

test('a record only the server has is accepted', () => {
  const r = merge({ local: [], remote: [env('a', 3)], syncedRev: {} });
  assert.equal(r.actions.get('a'), ACCEPT_NEW);
  assert.equal(r.envelopes.get('a').rev, 3);
  assert.equal(r.syncedRev.get('a'), 3);
  assert.deepEqual(r.conflicts, []);
});

test('a record only we have is queued to push, and not yet marked synced', () => {
  const r = merge({ local: [env('a', 1)], remote: [], syncedRev: {} });
  assert.equal(r.actions.get('a'), KEEP_LOCAL);
  assert.deepEqual(r.toPush.map((e) => e.id), ['a']);
  // Advancing the ancestor here would make a push that later fails look done,
  // and the next merge would then treat our unsent edit as already agreed.
  assert.equal(r.syncedRev.has('a'), false);
});

test('an untouched local record fast-forwards to the server', () => {
  const r = merge({
    local: [env('a', 2)],
    remote: [env('a', 5)],
    syncedRev: { a: 2 }, // we have not edited since we last agreed at 2
  });
  assert.equal(r.actions.get('a'), FAST_FORWARD);
  assert.equal(r.envelopes.get('a').rev, 5);
  assert.equal(r.syncedRev.get('a'), 5);
  assert.deepEqual(r.conflicts, []);
});

test('an untouched server record keeps the local edit', () => {
  const r = merge({
    local: [env('a', 6)],
    remote: [env('a', 2)],
    syncedRev: { a: 2 }, // the server is still where we left it
  });
  assert.equal(r.actions.get('a'), KEEP_LOCAL);
  assert.equal(r.envelopes.get('a').rev, 6);
  assert.deepEqual(r.toPush.map((e) => e.rev), [6]);
  assert.deepEqual(r.conflicts, []);
});

test('identical revisions are already in sync', () => {
  const r = merge({ local: [env('a', 4)], remote: [env('a', 4)], syncedRev: {} });
  assert.equal(r.actions.get('a'), IN_SYNC);
  assert.equal(r.syncedRev.get('a'), 4);
  assert.deepEqual(r.toPush, []);
});

test('two machines editing the same record is a conflict, never a silent choice', () => {
  const r = merge({
    local: [env('a', 7)],
    remote: [env('a', 9)],
    syncedRev: { a: 5 }, // both moved on from 5
  });
  assert.equal(r.actions.get('a'), CONFLICT);
  assert.equal(r.conflicts.length, 1);
  assert.equal(r.conflicts[0].kind, 'edit');
  // The machine in front of the user does not change under them...
  assert.equal(r.envelopes.get('a').rev, 7);
  // ...and the other side is parked, not discarded.
  assert.equal(r.conflicts[0].parked.rev, 9);
});

test('a deletion beats an edit racing it, and the edit is still recoverable', () => {
  const r = merge({
    local: [env('a', 8, true)],
    remote: [env('a', 9)],
    syncedRev: { a: 5 },
  });
  assert.equal(r.actions.get('a'), CONFLICT);
  assert.equal(r.conflicts[0].kind, 'delete');
  assert.equal(r.envelopes.get('a').deleted, true);
  assert.equal(r.conflicts[0].parked.rev, 9); // the surviving edit, kept
});

test('a deletion arriving from the server also wins', () => {
  const r = merge({
    local: [env('a', 8)],
    remote: [env('a', 9, true)],
    syncedRev: { a: 5 },
  });
  assert.equal(r.envelopes.get('a').deleted, true);
  assert.equal(r.conflicts[0].parked.rev, 8);
});

test('divergent revisions with no recorded ancestor are treated as a conflict', () => {
  // Happens when a push succeeded but the ancestor was not written down. The
  // safe reading is divergence, because assuming otherwise discards an edit.
  const r = merge({ local: [env('a', 3)], remote: [env('a', 4)], syncedRev: {} });
  assert.equal(r.actions.get('a'), CONFLICT);
});

test('a whole sync round settles', () => {
  const r = merge({
    local: [env('a', 2), env('b', 1), env('c', 9)],
    remote: [env('a', 5), env('d', 1), env('c', 3)],
    syncedRev: { a: 2, c: 3 },
  });
  assert.equal(r.actions.get('a'), FAST_FORWARD); // server moved
  assert.equal(r.actions.get('b'), KEEP_LOCAL); // ours alone
  assert.equal(r.actions.get('c'), KEEP_LOCAL); // we moved
  assert.equal(r.actions.get('d'), ACCEPT_NEW); // theirs alone
  assert.deepEqual(r.toPush.map((e) => e.id).sort(), ['b', 'c']);
  assert.deepEqual(r.conflicts, []);
  assert.equal(r.envelopes.size, 4);
});

test('the ancestor advances only once the server has accepted', () => {
  const first = merge({ local: [env('a', 4)], remote: [], syncedRev: {} });
  assert.equal(first.syncedRev.has('a'), false);

  const after = confirmPushed(first.syncedRev, first.toPush);
  assert.equal(after.get('a'), 4);

  // Next round: the server now agrees, and nothing is pending.
  const second = merge({ local: [env('a', 4)], remote: [env('a', 4)], syncedRev: after });
  assert.equal(second.actions.get('a'), IN_SYNC);
  assert.deepEqual(second.toPush, []);
});

test('merge does not mutate what it was given', () => {
  const local = [env('a', 1)];
  const syncedRev = new Map([['a', 1]]);
  merge({ local, remote: [env('a', 2)], syncedRev });
  assert.equal(local.length, 1);
  assert.equal(syncedRev.get('a'), 1);
});

test('equal revision numbers with different content are a conflict, not a match', () => {
  // The bug the integration test found. `rev` is a per-record counter bumped
  // locally, so two machines editing from rev 1 both reach rev 2 with different
  // content. Trusting the number alone loses one edit and reports success.
  const local = { ...env('a', 2), ct: 'from-b' };
  const remote = { ...env('a', 2), ct: 'from-a' };
  const r = merge({ local: [local], remote: [remote], syncedRev: { a: 1 } });

  assert.equal(r.actions.get('a'), CONFLICT);
  assert.equal(r.conflicts.length, 1);
  assert.equal(r.envelopes.get('a').ct, 'from-b'); // ours stays on screen
  assert.equal(r.conflicts[0].parked.ct, 'from-a'); // theirs is kept
  assert.deepEqual(r.toPush.map((e) => e.ct), ['from-b']);
});

test('equal revisions with identical bytes really are in sync', () => {
  const r = merge({ local: [env('a', 2)], remote: [env('a', 2)], syncedRev: { a: 1 } });
  assert.equal(r.actions.get('a'), IN_SYNC);
  assert.deepEqual(r.toPush, []);
  assert.deepEqual(r.conflicts, []);
});

// The server chooses the global sequence number freely, so guardRollback in
// sync.js cannot see a per-record rollback: a hostile server re-serves an OLD
// but genuinely-authentic envelope (this client really sealed it at that rev,
// so its AAD verifies) under a fresh sequence number. Before the fix, the
// fast-forward branch accepted it because it only checked l.rev === base,
// never that the remote had actually moved forward.

test('a rotated password is not rolled back by a re-served old envelope', () => {
  // The user rotated a leaked password (rev 1 → 2) and synced; the server
  // then re-serves the authentic rev-1 envelope holding the leaked password.
  const r = merge({
    local: [env('a', 2)],
    remote: [env('a', 1)],
    syncedRev: { a: 2 },
  });
  assert.equal(r.actions.get('a'), ROLLBACK);
  // The rotated password stays, and is pushed so the server is corrected even
  // by a caller that never looks at rolledBack.
  assert.equal(r.envelopes.get('a').rev, 2);
  assert.deepEqual(r.toPush.map((e) => e.rev), [2]);
  // The ancestor does not regress; confirmPushed advances it, as always.
  assert.equal(r.syncedRev.get('a'), 2);
  // And the attack is named, not healed quietly — sync.js refuses loudly on
  // the global sequence, and this is the same fact one level down.
  assert.equal(r.rolledBack.length, 1);
  assert.equal(r.rolledBack[0].id, 'a');
  assert.equal(r.rolledBack[0].remote.rev, 1);
});

test('a deleted record is not resurrected by a re-served live envelope', () => {
  // The user deleted the record (tombstone at rev 2) and synced; the server
  // re-serves the live rev-1 envelope, password and all. Before the fix the
  // fast-forward `continue` ran before the tombstone-wins logic ever could.
  const r = merge({
    local: [env('a', 2, true)],
    remote: [env('a', 1)],
    syncedRev: { a: 2 },
  });
  assert.equal(r.actions.get('a'), ROLLBACK);
  assert.equal(r.envelopes.get('a').deleted, true);
  assert.deepEqual(r.toPush.map((e) => e.deleted), [true]);
  assert.equal(r.rolledBack.length, 1);
});

test('a re-served old envelope is a rollback even when we also edited', () => {
  // Base 5, local at 7, and the server serving 3 — something it already
  // acknowledged moving past. That is not a fork to offer the user (the
  // "other version" would be their own leaked password); it is the server
  // going backwards, and it is named as such.
  const r = merge({
    local: [env('a', 7)],
    remote: [env('a', 3)],
    syncedRev: { a: 5 },
  });
  assert.equal(r.actions.get('a'), ROLLBACK);
  assert.equal(r.envelopes.get('a').rev, 7);
  assert.deepEqual(r.toPush.map((e) => e.rev), [7]);
  assert.deepEqual(r.conflicts, []);
  assert.equal(r.rolledBack.length, 1);
});

test('a tombstone is never discarded by a lower-rev live envelope, with no ancestor', () => {
  // No recorded ancestor, so the rollback check cannot fire; the divergence
  // path must still let the tombstone win rather than resurrect the record.
  const r = merge({
    local: [env('a', 5, true)],
    remote: [env('a', 3)],
    syncedRev: {},
  });
  assert.equal(r.envelopes.get('a').deleted, true);
  assert.equal(r.actions.get('a'), CONFLICT);
  assert.equal(r.conflicts[0].kind, 'delete');
});

test('a genuine fast-forward still works, and reports no rollback', () => {
  // The fix must not break normal sync: the server really did move forward,
  // so the remote is adopted exactly as before.
  const r = merge({
    local: [env('a', 2)],
    remote: [env('a', 3)],
    syncedRev: { a: 2 },
  });
  assert.equal(r.actions.get('a'), FAST_FORWARD);
  assert.equal(r.envelopes.get('a').rev, 3);
  assert.equal(r.syncedRev.get('a'), 3);
  assert.deepEqual(r.toPush, []);
  assert.deepEqual(r.rolledBack, []);
});

test('a same-numbered tombstone still beats a same-numbered edit', () => {
  const local = { ...env('a', 2), deleted: true };
  const r = merge({ local: [local], remote: [env('a', 2)], syncedRev: { a: 1 } });
  assert.equal(r.actions.get('a'), CONFLICT);
  assert.equal(r.conflicts[0].kind, 'delete');
  assert.equal(r.envelopes.get('a').deleted, true);
});
