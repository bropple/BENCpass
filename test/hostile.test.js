// Deterministic, single-purpose hostile-server tests.
//
// The model property test (model.test.js) drives a hostile server through
// random operation sequences and checks broad invariants. These tests instead
// pin one attack each to one exact SyncError code, because the property that
// matters here is not only "the data survived" but "the client REFUSED LOUDLY":
// a rollback or a tamper that is healed quietly leaves the data correct and so
// passes every data-outcome invariant, while hiding from the person syncing the
// one fact they most need — that the thing on the other end is a restored backup
// or an attacker, not the server they think it is. Silencing guardRecordRollback
// or the applyEnvelopes tamper check would pass the honest property test; it
// fails here.
//
// Pure JavaScript, no Go server: syncOnce only ever calls getMeta, getRecords
// and putRecords on its client, so a small in-memory stand-in exercises every
// path the real server would, and these run inside `npm test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Vault } from '../src/core/vault.js';
import { syncOnce, emptySyncState, SyncError } from '../src/core/sync.js';

const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };
const PASSWORD = 'hunter2';

// Honest model of server/store.go, enough for syncOnce: one global sequence,
// compare-and-swap on If-Match, refuses a batch that moves any record's
// revision backwards, `since` returns everything written after the sequence.
class MemServer {
  constructor() {
    this.seq = 0;
    this.meta = null;
    this.records = new Map();
  }
  async getMeta() {
    return { meta: this.meta ? structuredClone(this.meta) : null, seq: this.seq };
  }
  async putMeta(meta, ifMatch = null) {
    if (ifMatch !== null && Number(ifMatch) !== this.seq) {
      throw new SyncError('meta push failed (409: conflict)', 'meta');
    }
    this.seq++;
    this.meta = structuredClone(meta);
    return this.seq;
  }
  async getRecords(since = 0) {
    const records = [...this.records.values()]
      .filter((e) => e.seq > since)
      .map((e) => structuredClone(e));
    return { seq: this.seq, records };
  }
  async putRecords(records, ifMatch) {
    if (ifMatch === null) {
      if (this.seq !== 0) return { status: 428, seq: this.seq, error: 'If-Match required' };
    } else if (Number(ifMatch) !== this.seq) {
      return { status: 409, seq: this.seq, error: 'conflict' };
    }
    for (const r of records) {
      const old = this.records.get(r.id);
      if (old && r.rev < old.rev) {
        return { status: 422, seq: this.seq, error: `revision backwards: ${r.id}` };
      }
    }
    this.seq++;
    for (const r of records) this.records.set(r.id, { ...structuredClone(r), seq: this.seq });
    return { status: 200, seq: this.seq };
  }
}

// Two machines sharing one vault key, exactly as two enrolled devices do: the
// second loads the same header and unwraps the same key.
async function twoMachines() {
  const a = await Vault.create({ password: PASSWORD, kdf: FAST });
  const meta = a.toJSON().meta;
  const b = Vault.load({ meta: structuredClone(meta), envelopes: [], syncedRev: {} });
  await b.unlock(PASSWORD);
  return { a, b };
}

test('a server that lowers the global sequence is refused with code rollback', async () => {
  const server = new MemServer();
  const { a } = await twoMachines();
  const state = emptySyncState();

  await a.add({ title: 'Bank', password: 'secret' });
  await syncOnce(a, server, state);
  assert.ok(state.highestSeq > 0);

  // A restored-from-backup server, or something on the LAN replaying an old
  // copy, serves a LOWER sequence. It must be refused, not believed.
  const rolledBack = {
    getMeta: () => server.getMeta(),
    putRecords: (r, m) => server.putRecords(r, m),
    getRecords: async () => ({ seq: state.highestSeq - 1, records: [] }),
  };
  await assert.rejects(
    () => syncOnce(a, rolledBack, state),
    (err) => err instanceof SyncError && err.code === 'rollback',
  );
});

test('a re-served older revision under a bumped sequence is refused, not healed quietly', async () => {
  const server = new MemServer();
  const { a } = await twoMachines();
  const state = emptySyncState();

  const id = await a.add({ title: 'Bank', password: 'leaked' });
  await syncOnce(a, server, state);
  const stale = structuredClone(server.records.get(id)); // authentic pre-rotation envelope

  await a.update(id, { password: 'rotated' });
  await syncOnce(a, server, state);

  // The stale envelope is genuine — really sealed at that rev — so it opens.
  // guardRollback (global) is dodged by inflating the sequence; the record-level
  // guard is the only thing that can catch it, and it must.
  const hostile = {
    getMeta: () => server.getMeta(),
    getRecords: async () => ({ seq: state.highestSeq + 1, records: [stale] }),
    putRecords: async () => ({ status: 200, seq: state.highestSeq + 2 }),
  };
  await assert.rejects(
    () => syncOnce(a, hostile, state),
    (err) => err instanceof SyncError && err.code === 'rollback' && /older revision/.test(err.message),
  );
  assert.equal(a.get(id).password, 'rotated', 'the rotation must hold');
});

test('a flipped deleted bit contradicting the sealed body is refused with code tampered', async () => {
  const server = new MemServer();
  const { a, b } = await twoMachines();
  const sa = emptySyncState();
  const sb = emptySyncState();

  const id = await a.add({ title: 'Bank', password: 'live' });
  await syncOnce(a, server, sa);
  await syncOnce(b, server, sb); // b now holds R1 live at rev 1

  await a.update(id, { password: 'live2' }); // authentic rev 2, still live
  const rev2 = structuredClone(a.envelopes.get(id));
  const flipped = { ...rev2, deleted: true }; // the server lies: it says deleted

  // b is unlocked, so applyEnvelopes opens the sealed body, sees it is NOT
  // deleted, and the flag says it is — a contradiction no client ever writes.
  // It is refused before anything is adopted, loudly.
  const hostile = {
    getMeta: () => server.getMeta(),
    getRecords: async () => ({ seq: server.seq + 1, records: [flipped] }),
    putRecords: (r, m) => server.putRecords(r, m),
  };
  await assert.rejects(
    () => syncOnce(b, hostile, sb),
    (err) => err?.code === 'tampered',
  );
  // And the vault is left readable — a refused batch must not wedge it.
  assert.equal(b.get(id).password, 'live', 'b keeps the record it already had');
});

test('a flipped bit at an equal rev leaves the plaintext and envelope maps consistent', async () => {
  // The hardened hostile model found this: a server flips the cleartext deleted
  // bit on a record we already hold, leaving id, rev, n and ct untouched — same
  // ciphertext, opposite tombstone claim. applyEnvelopes' fast-path skipped it
  // on ct alone, so merge's adopted tombstone landed in the envelope map while
  // the live record stayed in the plaintext map. The two disagreed for ever,
  // and the fork that inconsistency produced later reverted another machine's
  // live password. The record must stay live, the envelope must agree with the
  // plaintext, and no duplicate may appear.
  const server = new MemServer();
  const { a, b } = await twoMachines();
  const sa = emptySyncState();
  const sb = emptySyncState();

  const id = await a.add({ title: 'Bank', password: 'live' });
  await syncOnce(a, server, sa);
  await syncOnce(b, server, sb); // b holds R1 live at rev 1

  const authentic = structuredClone(server.records.get(id));
  const flipped = { ...authentic, deleted: true }; // same rev/n/ct, flag flipped

  const hostile = {
    getMeta: () => server.getMeta(),
    getRecords: async () => ({ seq: server.seq + 1, records: [flipped] }),
    putRecords: (r, m) => server.putRecords(r, m),
  };
  await syncOnce(b, hostile, sb).catch(() => {}); // accept or refuse; either is legal

  // Whatever it did, it must not have left the two maps disagreeing.
  const env = b.envelopes.get(id);
  const live = b.list().filter((r) => r.id === id);
  if (env && !env.deleted) {
    assert.equal(live.length, 1, 'a live envelope must have exactly one live record, not zero and not a duplicate');
    assert.equal(b.get(id).password, 'live', 'the record must keep its live password');
  } else {
    // If it chose to honour the tombstone, the record must be gone from view —
    // never live-in-plaintext-but-deleted-in-envelope.
    assert.equal(live.length, 0, 'a tombstoned envelope must not leave a live record behind it');
  }
  // No stray duplicate carrying the same password under a different id.
  assert.equal(
    b.list().filter((r) => r.password === 'live').length <= 1,
    true,
    'the flip must not manufacture a duplicate of the live record',
  );
});

test('an undecryptable envelope adopted while locked becomes damaged, never a lockout', async () => {
  const server = new MemServer();
  const { a, b } = await twoMachines();
  const sa = emptySyncState();
  const sb = emptySyncState();

  const id = await a.add({ title: 'Bank', password: 'live' });
  await syncOnce(a, server, sa);

  // Random bytes where the ciphertext should be, at a higher rev so merge
  // adopts it. A LOCKED sync has no key to check it with.
  const authentic = structuredClone(server.records.get(id));
  const garbage = { ...authentic, rev: authentic.rev + 1, ct: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
  const hostile = {
    getMeta: () => server.getMeta(),
    getRecords: async () => ({ seq: server.seq + 1, records: [garbage] }),
    putRecords: (r, m) => server.putRecords(r, m),
  };

  b.lock();
  // The locked sync adopts whatever it is served — it cannot yet tell garbage
  // from a real record. That must not throw here.
  await syncOnce(b, hostile, sb).catch((err) => {
    // A conflict-locked refusal would be fine; a decrypt error must not escape
    // a locked sync, which has no key to decrypt with.
    assert.equal(err?.code, 'conflict-locked', `locked sync threw ${err?.code}: ${err?.message}`);
  });

  // The unlock is the moment of truth: before the brittle-unlock fix, one
  // fabricated record threw here and shut the vault for ever. Now it is named
  // as damaged and everything else opens.
  await assert.doesNotReject(() => b.unlock(PASSWORD));
  assert.ok(b.damaged.includes(id), 'the undecryptable record must be reported as damaged');
});

test('a push the server claims it accepted but did not store is caught by read-back', async () => {
  // The server answers 200 and advances its sequence — exactly what an accepted
  // write looks like — while storing nothing. Before read-back verification the
  // client marked the record as agreed and the write evaporated silently; now
  // the read-back finds it missing, the sync fails loudly, and nothing is
  // marked as synced, so the same envelope is pushed again next round.
  const server = new MemServer();
  const { a, b } = await twoMachines();
  const sa = emptySyncState();
  const sb = emptySyncState();

  await a.add({ title: 'Bank', password: 'precious' });

  let drop = true;
  const lying = {
    getMeta: () => server.getMeta(),
    putMeta: (m, i) => server.putMeta(m, i),
    getRecords: (s) => server.getRecords(s),
    putRecords: async (records, ifMatch) => {
      if (drop) {
        drop = false;
        server.seq++; // the sequence moves exactly as an accepted write would
        return { status: 200, seq: server.seq };
      }
      return server.putRecords(records, ifMatch);
    },
  };

  await assert.rejects(
    () => syncOnce(a, lying, sa),
    (err) => err instanceof SyncError && err.code === 'dropped-push',
  );

  // Fail-safe: the ancestor map must not have advanced, so an honest round
  // afterwards re-pushes the record and it genuinely lands.
  const res = await syncOnce(a, server, sa);
  assert.ok(res.pushed >= 1, 'the dropped record must be pushed again, not marked as agreed');
  await syncOnce(b, server, sb);
  assert.ok(
    b.list().some((r) => r.password === 'precious'),
    'the record reaches the second machine once the server is honest',
  );
});

test('an accepted push whose read-back was refused must not later steamroll a newer edit', async () => {
  // The B:revert the hostile model found once read-back existed. A's push is
  // ACCEPTED and stored, but the read-back after it is refused (a lowered
  // sequence), so the sync throws and A never confirms the ancestor. B then
  // builds rev 2 on top of A's stored rev 1. When A next syncs it holds rev 1
  // with no recorded ancestor against a rev-2 remote — and the old merge kept
  // A's stale copy and superseded it ABOVE rev 2, reverting B's newer password
  // on every machine. The remote must win; A's copy is parked, not pushed.
  const server = new MemServer();
  const { a, b } = await twoMachines();
  const sa = emptySyncState();
  const sb = emptySyncState();

  const id = await a.add({ title: 'Bank', password: 'v1' });

  let refuseReadBack = true;
  const flaky = {
    getMeta: () => server.getMeta(),
    putMeta: (m, i) => server.putMeta(m, i),
    putRecords: (r, m) => server.putRecords(r, m), // the push itself lands
    getRecords: async (s) => {
      if (refuseReadBack && server.records.has(id)) {
        // The pull straight after the accepted push: serve a lowered sequence,
        // which guardRollback refuses — the 200 has landed, the ancestor has not.
        refuseReadBack = false;
        return { seq: 0, records: [] };
      }
      return server.getRecords(s);
    },
  };

  await assert.rejects(
    () => syncOnce(a, flaky, sa),
    (err) => err instanceof SyncError && err.code === 'rollback',
  );
  assert.ok(server.records.get(id), 'the push must genuinely have been stored');

  // B builds on A's stored rev 1.
  await syncOnce(b, server, sb);
  await b.update(id, { password: 'v2' });
  await syncOnce(b, server, sb);

  // A syncs against the now-honest server. Its rev 1 has no ancestor; the
  // rev-2 remote must be adopted, and v1 survives only as a parked fork.
  await syncOnce(a, server, sa);
  assert.equal(a.get(id).password, 'v2', "A must adopt B's newer edit, not steamroll it");

  await syncOnce(a, server, sa);
  await syncOnce(b, server, sb);
  assert.equal(b.get(id).password, 'v2', "B's edit must never revert to v1");
  assert.ok(
    a.list().some((r) => r.conflictOf === id && r.password === 'v1'),
    "A's own copy is kept as a visible conflict fork, not dropped",
  );
});

test('a read-back finding the record already superseded is not a false alarm', async () => {
  // Between this machine's push and its read-back another machine can write a
  // newer revision of the same record. The pushed bytes are then absent from
  // the read-back — legitimately. That is not a dropped write, and screaming
  // about it would make every busy vault cry wolf; the next ordinary pull
  // settles the newer revision the usual way.
  const server = new MemServer();
  const { a, b } = await twoMachines();
  const sa = emptySyncState();
  const sb = emptySyncState();

  const id = await a.add({ title: 'Bank', password: 'v1' });
  await syncOnce(a, server, sa);
  await syncOnce(b, server, sb);

  await a.update(id, { password: 'v2' });

  const racing = {
    getMeta: () => server.getMeta(),
    putMeta: (m, i) => server.putMeta(m, i),
    getRecords: (s) => server.getRecords(s),
    putRecords: async (records, ifMatch) => {
      const out = await server.putRecords(records, ifMatch);
      if (out.status === 200 && !racing.done) {
        racing.done = true;
        // b pulls a's rev 2, edits it to rev 3 and pushes — all in the gap
        // between a's accepted push and a's read-back.
        await syncOnce(b, server, sb);
        await b.update(id, { password: 'v3' });
        await syncOnce(b, server, sb);
      }
      return out;
    },
  };

  const res = await syncOnce(a, racing, sa);
  assert.ok(res.pushed >= 1, 'the sync must complete — a superseded push is not a dropped push');
});

test('a 409 between pull and push is retried and the sync still completes', async () => {
  // Real machines on one network hit the compare-and-swap retry constantly:
  // another device writes between this one's pull and its push. The honest
  // model never interleaves within a syncOnce, so this forces exactly one 409
  // and proves the retry branch converges rather than throwing.
  const server = new MemServer();
  const { a, b } = await twoMachines();
  const sa = emptySyncState();
  const sb = emptySyncState();

  await a.add({ title: 'A record', password: 'a1' });
  await syncOnce(a, server, sa);
  await syncOnce(b, server, sb);

  await b.add({ title: 'B record', password: 'b1' });

  let firstPush = true;
  const racing = {
    getMeta: () => server.getMeta(),
    getRecords: (s) => server.getRecords(s),
    putRecords: async (records, ifMatch) => {
      if (firstPush) {
        firstPush = false;
        // Another device slipped a write in just now, so this If-Match is stale.
        return { status: 409, seq: server.seq, error: 'conflict' };
      }
      return server.putRecords(records, ifMatch);
    },
  };

  const res = await syncOnce(b, racing, sb);
  assert.equal(firstPush, false, 'the 409 branch must have been taken');
  assert.ok(res.pushed >= 1, 'b still pushed its record after the retry');

  // And a follows to confirm b's record actually landed.
  await syncOnce(a, server, sa);
  assert.ok(a.list().some((r) => r.password === 'b1'), 'b1 reached a after the retry');
});
