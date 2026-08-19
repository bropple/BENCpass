// Model-based (randomised, property) test for the sync engine.
//
// Why this exists: the two worst bugs this project has had were both "a
// revision arrangement nobody thought to consider" inside merge(). Humans read
// that function four times and walked past the first one. This file makes the
// machine enumerate arrangements instead: it simulates three machines sharing
// one vault through an in-memory model of bencpass-server, drives them with
// randomised operation sequences, and after every step checks invariants that
// are stated about USER-VISIBLE outcomes, not about how merge() happens to be
// implemented today — so it survives concurrent rework of conflict handling.
//
// The invariants (verbatim from the brief):
//
//   A. NO SILENT LOSS       — a record a user created and did not delete is
//                             present on every machine that has synced.
//   B. NO LIVE REGRESSION   — a plaintext password on a machine never reverts
//                             to a value superseded on that same machine.
//   C. CONVERGENCE          — after every machine syncs twice with no user
//                             edits in between, all machines and the server
//                             agree, and no conflict reappears.
//   D. DELETIONS STICK, AND ONLY DELIBERATE ONES.
//   E. NOTHING IS CLAIMED THAT IS NOT TRUE — a conflict reported as parked
//                             must actually be retrievable afterwards.
//
// A separate property runs the same machines against a HOSTILE server that may
// re-serve any authentic envelope it has ever seen at any global sequence.
// There the client may refuse to sync (throwing is fine), but if it accepts,
// invariants B and D must still hold.
//
// Determinism: a small PRNG (mulberry32) seeded from MODEL_SEED (default
// 0xBEC0DE). Every failure prints the seed and a MINIMAL operation sequence,
// found by delta-debugging the failing sequence down while the same class of
// violation persists. Set MODEL_CASES to run more cases than the CI default.
//
// The test is EXPECTED to fail while known bugs are unfixed: a failure report
// listing findings is this file doing its job. Do not weaken the invariants.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Vault } from '../src/core/vault.js';
import { syncOnce, emptySyncState, SyncError } from '../src/core/sync.js';
import { deriveMasterKey, unwrapVaultKey, importKey, openRecord } from '../src/core/crypto.js';
import { fromB64 } from '../src/core/bytes.js';

const BASE_SEED = Number(process.env.MODEL_SEED ?? 0xbec0de);
const CASES = Number(process.env.MODEL_CASES ?? 200);
const HOSTILE_CASES = Number(process.env.MODEL_CASES ?? 120);
const MAX_SHRINK_RUNS = 500;

const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };
const PASSWORD = 'hunter2';

// ---- deterministic PRNG ----------------------------------------------------

function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---- one Argon2 for the whole suite ----------------------------------------
//
// Every machine in every case shares one vault key, exactly as real machines
// joining one vault do. Deriving it once and unlocking with the raw bytes
// keeps a run of hundreds of cases to seconds of AES, not minutes of Argon2.

let templateMeta = null;
let vaultKeyBytes = null;
let peekKey = null; // the test's own handle on the vault key, to read parked envelopes

async function ensureTemplate() {
  if (vaultKeyBytes) return;
  const t = await Vault.create({ password: PASSWORD, kdf: FAST });
  templateMeta = t.toJSON().meta;
  const masterKey = await deriveMasterKey(
    PASSWORD,
    fromB64(templateMeta.kdf.salt),
    templateMeta.kdf,
  );
  vaultKeyBytes = await unwrapVaultKey(templateMeta.wraps.password, masterKey);
  peekKey = await importKey(vaultKeyBytes, { extractable: false });
}

async function newMachine(name, server) {
  const vault = Vault.load({
    meta: structuredClone(templateMeta),
    envelopes: [],
    syncedRev: {},
  });
  await vault.unlockWithVaultKey(vaultKeyBytes);
  return {
    name,
    vault,
    client: server, // the server model speaks the client surface syncOnce uses
    state: emptySyncState(),
    // Per-machine observation model, updated only from what the vault shows:
    lastSeen: new Map(), // id -> last password observed here
    superseded: new Map(), // id -> Set of passwords this machine moved past
    seenLive: new Set(), // ids that were ever live on this machine
    observedDeleted: new Set(), // ids this machine has seen disappear after a user delete
  };
}

const unlockMachine = (m) => m.vault.unlockWithVaultKey(vaultKeyBytes);

// ---- server models ---------------------------------------------------------

// Honest model of server/store.go: one global sequence, compare-and-swap on
// If-Match, refuses a batch that moves any record's revision backwards,
// `since` returns everything written after the given sequence.
class MemServer {
  constructor() {
    this.seq = 0;
    this.meta = null;
    this.records = new Map(); // id -> envelope (with .seq)
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
        return {
          status: 422,
          seq: this.seq,
          error: `record revision would go backwards: ${r.id} at rev ${r.rev}, store has ${old.rev}`,
        };
      }
    }
    this.seq++;
    for (const r of records) this.records.set(r.id, { ...structuredClone(r), seq: this.seq });
    return { status: 200, seq: this.seq };
  }
}

// Hostile model: everything it serves is AUTHENTIC — an envelope some client
// really sealed and pushed — but it may re-serve any envelope it has ever
// seen, for any record, at any global sequence it likes (including one high
// enough to sail past guardRollback). This is exactly the shape of the
// re-served-stale-envelope attack that merge() used to fast-forward into.
class HostileServer extends MemServer {
  constructor(rng, trace) {
    super();
    this.rng = rng;
    this.trace = trace;
    this.history = new Map(); // id -> [every envelope ever accepted]
  }
  async putRecords(records, ifMatch) {
    const out = await super.putRecords(records, ifMatch);
    if (out.status === 200) {
      for (const r of records) {
        if (!this.history.has(r.id)) this.history.set(r.id, []);
        this.history.get(r.id).push(structuredClone(r));
      }
    }
    return out;
  }
  async getRecords(since = 0) {
    const base = await super.getRecords(since);
    if (this.history.size && this.rng() < 0.5) {
      const ids = [...this.history.keys()];
      const id = ids[Math.floor(this.rng() * ids.length)];
      const versions = this.history.get(id);
      const chosen = structuredClone(versions[Math.floor(this.rng() * versions.length)]);
      // Serve it under a bumped global sequence, and adopt that sequence so
      // the follow-up push's If-Match lines up — the attacker WANTS the sync
      // to be accepted.
      const fakeSeq = Math.max(base.seq, this.seq) + 1 + Math.floor(this.rng() * 3);
      chosen.seq = fakeSeq;
      this.seq = fakeSeq;
      this.trace.push(
        `      (hostile) re-served ${short(id)} rev ${chosen.rev}` +
          `${chosen.deleted ? ' (tombstone)' : ''} at seq ${fakeSeq}`,
      );
      return { seq: fakeSeq, records: [...base.records.filter((e) => e.id !== id), chosen] };
    }
    return base;
  }
}

const short = (id) => String(id).slice(0, 8);

// ---- violations ------------------------------------------------------------

class Violation extends Error {
  constructor(key, detail) {
    super(`${key}: ${detail}`);
    this.key = key; // e.g. 'E:delete' — invariant letter, then the failure mode
    this.detail = detail;
  }
}

// ---- op generation ---------------------------------------------------------
//
// Ops are fully materialised up front (machine index, pick index) so a run is
// a pure function of the op list — which is what makes shrinking honest.
// Random weights naturally produce every scenario the brief names: sync in
// different orders, sync twice, a machine offline for many rounds, and two
// machines editing the same record before either syncs.

function genOps(rng, nMachines, len) {
  const ops = [{ op: 'add', m: 0 }];
  for (let i = 1; i < len; i++) {
    const r = rng();
    const m = Math.floor(rng() * nMachines);
    if (r < 0.16) ops.push({ op: 'add', m });
    else if (r < 0.42) ops.push({ op: 'edit', m, pick: Math.floor(rng() * 8) });
    else if (r < 0.52) ops.push({ op: 'del', m, pick: Math.floor(rng() * 8) });
    else if (r < 0.8) ops.push({ op: 'sync', m });
    else if (r < 0.88) ops.push({ op: 'syncLocked', m });
    else ops.push({ op: 'sync2', m });
  }
  return ops;
}

// ---- one run ---------------------------------------------------------------
//
// Executes a spec ({seed, ops, machines, hostile}) against fresh state.
// Returns { ok: true } or { ok: false, violation, trace }.
// `ignore` is a set of violation CLASSES already reported, skipped so the run
// can continue and surface the next class.

async function run(spec, ignore = new Set()) {
  await ensureTemplate();
  const trace = [];
  const rng = mulberry32(spec.seed);
  const server = spec.hostile ? new HostileServer(rng, trace) : new MemServer();
  const machines = [];
  for (let i = 0; i < spec.machines; i++) {
    machines.push(await newMachine('ABC'[i], server));
  }

  const world = {
    deletedByUser: new Set(),
    alias: new Map(), // id -> R1, R2, ... (user records) / F1, F2, ... (conflict forks)
    pwN: 0,
    recN: 0,
    forkN: 0,
    promises: [], // invariant E: parked plaintext that a merge promised to keep
  };
  const alias = (id) => world.alias.get(id) ?? short(id);

  const fail = (key, detail) => {
    if (ignore.has(key)) return;
    throw new Violation(key, detail);
  };

  // Observe a machine's user-visible state and check A, B and D against it.
  const observe = (m) => {
    if (m.vault.locked) return;
    const live = new Map(m.vault.list().map((r) => [r.id, r.password]));
    for (const id of live.keys()) {
      // A record no op created is a conflict fork minted by the sync layer.
      if (!world.alias.has(id)) world.alias.set(id, `F${++world.forkN}`);
    }
    for (const [id, pw] of live) {
      if (m.observedDeleted.has(id)) {
        fail(
          'D:resurrected',
          `${alias(id)} came back to life on ${m.name} after ${m.name} had seen it deleted`,
        );
      }
      if (m.superseded.get(id)?.has(pw)) {
        fail(
          'B:revert',
          `the password of ${alias(id)} on ${m.name} reverted to "${pw}", ` +
            `a value that machine had already moved past`,
        );
      }
      const prev = m.lastSeen.get(id);
      if (prev !== undefined && prev !== pw) {
        if (!m.superseded.has(id)) m.superseded.set(id, new Set());
        m.superseded.get(id).add(prev);
      }
      m.lastSeen.set(id, pw);
      m.seenLive.add(id);
    }
    for (const id of m.seenLive) {
      if (live.has(id)) continue;
      if (!world.deletedByUser.has(id)) {
        fail(
          'A:vanished',
          `${alias(id)} vanished from ${m.name} though no user ever deleted it`,
        );
      }
      m.observedDeleted.add(id);
    }
  };
  const observeAll = () => {
    machines.forEach(observe);
    checkPromises();
  };

  // Invariant E: everything merge reports as parked must genuinely be
  // recoverable by the person on that machine. The test holds its own copy of
  // the vault key, so it opens the parked envelope itself and then demands
  // that the plaintext password be reachable through the vault's public
  // surface: either some record in list() carries it (the current copy, or a
  // "(conflict)" fork made by resolveParked), or it is still pending in the
  // persisted parked queue (a locked sync parks now and forks at the next
  // unlocked pass). "Pending" that never resolves is caught because the
  // promise is re-checked after every later operation and after the settle
  // passes, which run unlocked.
  const recordPromises = async (m, res) => {
    for (const c of res.conflicts ?? []) {
      if (!c.parked) continue;
      let body;
      try {
        body = await openRecord(peekKey, c.parked.id, c.parked.rev, c.parked);
      } catch {
        continue; // not sealed under this vault's key; nothing was promised
      }
      if (!body || body.deleted || body.password === undefined) continue;
      world.promises.push({
        m,
        kind: c.kind,
        id: c.parked.id,
        rev: c.parked.rev,
        n: c.parked.n,
        password: body.password,
      });
    }
  };

  const checkPromises = () => {
    world.promises = world.promises.filter((p) => {
      const m = p.m;
      if (m.vault.locked) return true; // cannot look yet; keep the promise
      if (m.vault.list().some((r) => r.password === p.password)) return false; // recovered
      const parked = m.vault.toJSON().parked ?? [];
      if (parked.some((e) => e.id === p.id && e.rev === p.rev && e.n === p.n)) return true;
      fail(
        `E:${p.kind}`,
        `merge on ${m.name} reported the losing side of a ${p.kind} conflict on ` +
          `${alias(p.id)} (rev ${p.rev}, password "${p.password}") as parked/kept, ` +
          `but that password is not reachable on ${m.name} through list() or any ` +
          `"(conflict)" fork, and it is no longer in the parked queue — ` +
          `the promised recovery does not exist`,
      );
      return false; // only reached when this class of violation is ignored
    });
  };

  // Invariant A/D against the server, honest runs only: after a successful
  // sync this machine must hold every record the server holds live (unless a
  // user deleted it and the tombstone simply has not landed yet), and the
  // server must never hold a tombstone nobody asked for.
  const checkCompleteness = (m) => {
    for (const [id, env] of server.records) {
      if (env.deleted) {
        if (!world.deletedByUser.has(id)) {
          fail('D:phantom-tombstone', `the server holds a tombstone for ${alias(id)}, which no user deleted`);
        }
        continue;
      }
      if (world.deletedByUser.has(id)) continue;
      const have = m.vault.envelopes.get(id);
      if (!have || have.deleted) {
        fail(
          'A:missing-after-sync',
          `${m.name} completed a sync while the server holds live ${alias(id)}, ` +
            `but ${m.name} does not have it`,
        );
      }
    }
  };

  const doSync = async (m, label) => {
    try {
      const res = await syncOnce(m.vault, m.client, m.state);
      trace.push(
        `      ${label}: pulled ${res.pulled}, pushed ${res.pushed}, ` +
          `conflicts ${res.conflicts.length}, seq ${res.seq}`,
      );
      await recordPromises(m, res);
      if (!spec.hostile) checkCompleteness(m);
      return res;
    } catch (err) {
      if (err instanceof Violation) throw err;
      trace.push(`      ${label}: REFUSED (${err.code ?? 'error'}: ${err.message})`);
      return null; // refusing is legal; convergence decides if it is fatal
    }
  };

  const liveIds = (m) =>
    m.vault
      .list()
      .map((r) => r.id)
      .sort((a, b) => Number(alias(a).slice(1)) - Number(alias(b).slice(1)));

  try {
    let step = 0;
    for (const o of spec.ops) {
      step++;
      const m = machines[o.m % machines.length];
      switch (o.op) {
        case 'add': {
          const pw = `pw${++world.pwN}`;
          const id = await m.vault.add({ title: `rec`, username: 'u', password: pw });
          world.alias.set(id, `R${++world.recN}`);
          trace.push(`${String(step).padStart(3)}. ${m.name}: add ${alias(id)} = ${pw}`);
          break;
        }
        case 'edit': {
          const ids = liveIds(m);
          if (!ids.length) {
            trace.push(`${String(step).padStart(3)}. ${m.name}: edit (nothing to edit — skipped)`);
            break;
          }
          const id = ids[o.pick % ids.length];
          const pw = `pw${++world.pwN}`;
          await m.vault.update(id, { password: pw });
          trace.push(`${String(step).padStart(3)}. ${m.name}: edit ${alias(id)} -> ${pw}`);
          break;
        }
        case 'del': {
          const ids = liveIds(m);
          if (!ids.length) {
            trace.push(`${String(step).padStart(3)}. ${m.name}: delete (nothing there — skipped)`);
            break;
          }
          const id = ids[o.pick % ids.length];
          await m.vault.remove(id);
          world.deletedByUser.add(id);
          trace.push(`${String(step).padStart(3)}. ${m.name}: delete ${alias(id)}`);
          break;
        }
        case 'sync': {
          trace.push(`${String(step).padStart(3)}. ${m.name}: sync`);
          await doSync(m, `${m.name} sync`);
          break;
        }
        case 'sync2': {
          trace.push(`${String(step).padStart(3)}. ${m.name}: sync twice`);
          await doSync(m, `${m.name} sync 1/2`);
          await doSync(m, `${m.name} sync 2/2`);
          break;
        }
        case 'syncLocked': {
          trace.push(`${String(step).padStart(3)}. ${m.name}: lock, sync while locked, unlock`);
          m.vault.lock();
          await doSync(m, `${m.name} sync (locked)`);
          await unlockMachine(m);
          break;
        }
        default:
          throw new Error(`unknown op ${o.op}`);
      }
      observeAll();
    }

    // ---- convergence epilogue (invariant C), honest runs only --------------
    //
    // No user edits from here on. Every machine syncs, round-robin, until a
    // full pass moves nothing. The brief's rule — every machine syncs twice —
    // maps to: any CONFLICT reported in pass 3 or later is drift (passes 1
    // and 2 are the two allowed syncs; pushes alone may legitimately need one
    // more pass to fan out). Not settling at all is likewise a failure.
    if (!spec.hostile) {
      const MAX_PASSES = 6;
      const fingerprint = () =>
        JSON.stringify(
          [...server.records.entries()]
            .map(([id, e]) => [id, e.rev, e.ct, e.deleted])
            .sort((a, b) => (a[0] < b[0] ? -1 : 1)),
        );
      let stable = false; // server content stopped changing and conflicts stopped
      let stillPushing = 0; // byte-identical re-pushes seen on the stable pass
      let prevFp = fingerprint();
      for (let pass = 1; pass <= MAX_PASSES && !stable; pass++) {
        let pushes = 0;
        let conflicts = 0;
        for (const m of machines) {
          if (m.vault.locked) await unlockMachine(m);
          const res = await doSync(m, `settle pass ${pass}, ${m.name}`);
          if (res === null) {
            fail(
              'C:sync-refused',
              `${m.name} cannot complete a sync during the settle passes — ` +
                `it will never converge (see the last REFUSED line in the trace)`,
            );
            continue;
          }
          pushes += res.pushed;
          conflicts += res.conflicts.length;
          if (pass >= 3 && res.conflicts.length) {
            fail(
              'C:conflict-drift',
              `${m.name} still reports ${res.conflicts.length} conflict(s) in settle pass ${pass}, ` +
                `with no user edits since pass 1 — the conflict reappears on every sync ` +
                `instead of resolving`,
            );
          }
          observeAll();
        }
        const fp = fingerprint();
        if (fp === prevFp && conflicts === 0) {
          // Nothing on the server changed in a whole pass: the DATA has
          // converged. Machines may still be re-pushing byte-identical
          // envelopes forever, which is a defect of its own, reported
          // separately so it cannot mask (or be mistaken for) real drift.
          stable = true;
          stillPushing = pushes;
        }
        prevFp = fp;
      }
      if (!stable) {
        fail(
          'C:no-quiesce',
          `after ${MAX_PASSES} full settle passes with no user edits, the server's ` +
            `content is still changing — sync never reaches a fixed point`,
        );
      }
      if (stillPushing) {
        fail(
          'C:perpetual-push',
          `the data converged, but machines re-push ${stillPushing} envelope(s) the server ` +
            `already acknowledged on EVERY sync, forever — merge treats "absent from the ` +
            `delta pull" as "never pushed" even when syncedRev says the server has it, ` +
            `so a quiet vault generates an unbounded write stream and the global ` +
            `sequence climbs on every poll`,
        );
      }

      // All machines identical, and the server agrees. Only meaningful once
      // the system stopped moving: comparing mid-flight states would blame
      // divergence on ordinary propagation delay.
      if (stable) await checkAgreement(machines, server, alias, fail);
    }
  } catch (err) {
    if (err instanceof Violation) return { ok: false, violation: err, trace };
    throw err;
  }
  return { ok: true, trace };
}

async function checkAgreement(machines, server, alias, fail) {
  for (const m of machines) if (m.vault.locked) await unlockMachine(m);
      const views = machines.map((m) => ({
        name: m.name,
        live: new Map(m.vault.list().map((r) => [r.id, r.password])),
      }));
      const describe = () =>
        views
          .map(
            (v) =>
              `${v.name}: { ${[...v.live].map(([id, pw]) => `${alias(id)}=${pw}`).join(', ')} }`,
          )
          .join('  |  ');
      const ref = views[0];
      for (const v of views.slice(1)) {
        const keys = new Set([...ref.live.keys(), ...v.live.keys()]);
        for (const id of keys) {
          if (ref.live.get(id) !== v.live.get(id)) {
            fail(
              'C:diverged',
              `after settling, machines disagree about ${alias(id)}: ${describe()}`,
            );
          }
        }
      }
      for (const [id, env] of server.records) {
        for (const m of machines) {
          const have = m.vault.envelopes.get(id);
          if (!have || have.rev !== env.rev || have.ct !== env.ct || have.deleted !== env.deleted) {
            fail(
              'C:server-disagrees',
              `after settling, the server's copy of ${alias(id)} (rev ${env.rev}` +
                `${env.deleted ? ', tombstone' : ''}) does not match ${m.name}'s ` +
                `(${have ? `rev ${have.rev}${have.deleted ? ', tombstone' : ''}` : 'absent'})`,
            );
          }
        }
      }
}

// ---- shrinking -------------------------------------------------------------
//
// Delta-debugging lite: repeatedly try dropping windows of operations, keeping
// any smaller sequence that still fails with the SAME CLASS of violation.
// Bounded by MAX_SHRINK_RUNS so a pathological case cannot stall CI.

async function shrink(spec, violation, ignore) {
  let ops = spec.ops;
  let best = { violation, trace: null };
  let runs = 0;
  let size = Math.max(1, ops.length >> 1);
  while (size >= 1 && runs < MAX_SHRINK_RUNS) {
    let removed = false;
    for (let i = 0; i + size <= ops.length && runs < MAX_SHRINK_RUNS; ) {
      const candidate = ops.slice(0, i).concat(ops.slice(i + size));
      runs++;
      const r = await run({ ...spec, ops: candidate }, ignore);
      if (!r.ok && r.violation.key === violation.key) {
        ops = candidate;
        best = { violation: r.violation, trace: r.trace };
        removed = true;
      } else {
        i++;
      }
    }
    if (!removed) size >>= 1;
    else size = Math.min(size, Math.max(1, ops.length >> 1));
  }
  // One clean rerun for the reported trace.
  const final = await run({ ...spec, ops }, ignore);
  if (!final.ok) best = { violation: final.violation, trace: final.trace };
  return { ops, ...best };
}

// ---- the drivers -----------------------------------------------------------

function formatFinding(i, f) {
  return [
    `[${i + 1}] invariant ${f.violation.key} (seed ${f.seed}, ${f.ops.length} ops, machines ${f.machines})`,
    `    ${f.violation.detail}`,
    `    minimal sequence:`,
    ...(f.trace ?? []).map((l) => `    ${l}`),
    '',
  ].join('\n');
}

// Runs cases, and each time a NEW kind of violation appears, shrinks it,
// records it, and re-sweeps with that kind ignored — so one broken invariant
// cannot mask the others behind it. `preIgnore` narrows a property to the
// invariants it is actually about (the hostile property is about B and D).
async function sweep({ hostile, cases, machines, name, preIgnore = [] }) {
  const findings = [];
  const ignore = new Set(preIgnore);
  for (let round = 0; round < 12; round++) {
    let found = null;
    for (let c = 0; c < cases && !found; c++) {
      const seed = (BASE_SEED + c * 1000003 + (hostile ? 7777777 : 0)) >>> 0;
      const genRng = mulberry32(seed ^ 0x9e3779b9);
      const ops = genOps(genRng, machines, 8 + Math.floor(genRng() * 12));
      const spec = { seed, ops, machines, hostile };
      const r = await run(spec, ignore);
      if (!r.ok) found = { spec, r };
    }
    if (!found) break;
    const small = await shrink(found.spec, found.r.violation, ignore);
    findings.push({
      seed: found.spec.seed,
      machines,
      ops: small.ops,
      violation: small.violation,
      trace: small.trace,
    });
    ignore.add(found.r.violation.key);
  }
  if (findings.length) {
    assert.fail(
      `\n${name}: the model found ${findings.length} distinct invariant violation(s).\n` +
        `Base seed ${BASE_SEED} (MODEL_SEED to vary, MODEL_CASES to run more).\n\n` +
        findings.map((f, i) => formatFinding(i, f)).join('\n'),
    );
  }
}

// ---- the tests -------------------------------------------------------------

// Harness sanity. Two parts, both of which must stay green even while the
// properties below are red, so a failure there can be trusted:
//  - an empty exchange (no records at all) settles and violates nothing;
//  - a quiet, conflict-free exchange keeps A, B, D and E. Convergence (C) is
//    deliberately not asserted here: even this exchange currently trips it,
//    because an acknowledged record is re-pushed on every sync (see the
//    C:perpetual-push finding of the property below). The property test owns
//    reporting that; this test only proves the observer does not cry wolf.
test('model: the harness itself is sound', async () => {
  const empty = await run({
    seed: 1,
    machines: 2,
    hostile: false,
    ops: [
      { op: 'sync', m: 0 },
      { op: 'sync', m: 1 },
    ],
  });
  assert.equal(
    empty.ok,
    true,
    `an exchange with no records violated an invariant:\n${empty.violation?.message}\n${empty.trace?.join('\n')}`,
  );

  const quietC = [
    'C:no-quiesce',
    'C:perpetual-push',
    'C:conflict-drift',
    'C:sync-refused',
    'C:diverged',
    'C:server-disagrees',
  ];
  const quiet = await run(
    {
      seed: 1,
      machines: 2,
      hostile: false,
      ops: [
        { op: 'add', m: 0 },
        { op: 'sync', m: 0 },
        { op: 'sync', m: 1 },
        { op: 'edit', m: 1, pick: 0 },
        { op: 'sync', m: 1 },
        { op: 'syncLocked', m: 0 },
        { op: 'del', m: 0, pick: 0 },
        { op: 'sync', m: 0 },
        { op: 'sync', m: 1 },
      ],
    },
    new Set(quietC),
  );
  assert.equal(
    quiet.ok,
    true,
    `a conflict-free exchange violated a non-convergence invariant:\n${quiet.violation?.message}\n${quiet.trace?.join('\n')}`,
  );
});

test('model: randomised operations against an honest server preserve invariants A-E', async () => {
  await sweep({ hostile: false, cases: CASES, machines: 3, name: 'HONEST SERVER' });
});

test('model: a hostile server re-serving authentic envelopes cannot make a client silently accept bad data', async () => {
  // This property is about what a client ACCEPTS from a hostile server:
  // refusing (throwing) is always legal, but accepted data must never revert
  // a live password (B) or delete/resurrect what the user did not (A, D).
  // The parked-conflict bookkeeping (E) is owned by the honest-server
  // property above; repeating it here would only report the same bug twice.
  await sweep({
    hostile: true,
    cases: HOSTILE_CASES,
    machines: 2,
    name: 'HOSTILE SERVER',
    preIgnore: ['E:delete', 'E:edit'],
  });
});

// Sequences the model has already found, pinned so they run on every seed and
// case count. Each was minimised by the shrinker; the seed it came from is
// noted for provenance, but the ops replay deterministically without it.
//
// THE LOCKED-CONFLICT WEDGE (found at MODEL_SEED=1, case seed 338001015).
// A machine that meets a tombstone-vs-edit conflict during a LOCKED sync is
// wedged permanently. settleConflicts on a locked vault parks the losing side
// but cannot supersede, so the stale local tombstone (rev 2) is pushed against
// a server that already holds rev 3 — a 422. By then state.seq and
// state.syncedRev have already advanced past the pull, so the next sync's
// delta no longer contains the remote record, merge sees "local only" and
// re-pushes the same stale tombstone with no conflict left to settle — 422,
// forever, unlocked or not. The machine never syncs again, its deletion never
// propagates, and its other edits stop propagating too (which is how this
// surfaced as C:diverged as well). settleConflicts' own comment — "the same
// conflict is re-detected until an unlocked sync settles it" — does not hold,
// because the failed push still advanced the ancestor state.
test('model regression: a conflict met on a locked sync must not wedge the machine forever', async () => {
  const r = await run(
    {
      seed: 338001015,
      machines: 3,
      hostile: false,
      ops: [
        { op: 'add', m: 2 }, //            C: add R1
        { op: 'sync', m: 2 }, //           C: push it
        { op: 'sync', m: 0 }, //           A: pull it
        { op: 'sync', m: 1 }, //           B: pull it
        { op: 'edit', m: 1, pick: 0 }, //  B: edit R1 (rev 2, one flavour)
        { op: 'edit', m: 2, pick: 0 }, //  C: edit R1 (rev 2, another flavour)
        { op: 'sync', m: 1 }, //           B: push rev 2
        { op: 'del', m: 0, pick: 0 }, //   A: delete R1 (tombstone rev 2, offline)
        { op: 'sync', m: 2 }, //           C: conflict, supersedes to rev 3
        { op: 'syncLocked', m: 0 }, //     A: meets the conflict LOCKED -> wedged
      ],
    },
    // The perpetual re-push of acknowledged envelopes is a separate defect
    // with its own finding in the property test; ignoring it here keeps this
    // regression pointed at exactly one bug.
    new Set(['C:perpetual-push']),
  );
  assert.equal(
    r.ok,
    true,
    `${r.violation?.message}\n\n${(r.trace ?? []).join('\n')}`,
  );
});
