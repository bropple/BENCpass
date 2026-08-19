// Causal three-way merge over envelopes.
//
// Pure, and deliberately key-free: it runs on a locked vault, because it needs
// only id, rev and the tombstone flag. That constraint is doing real work — it
// means the merge *cannot* consult a timestamp even if tempted, since every
// timestamp lives inside the ciphertext. Ordering therefore comes from
// causality alone and is correct under arbitrary clock skew.
//
// The common ancestor is `syncedRev[id]`: the revision this client last agreed
// with the server on.
//
//   local.rev  === base   →  only the remote moved  →  fast-forward
//   remote.rev === base   →  only we moved          →  keep ours, push it
//   remote.rev  <  base   →  the server went back   →  keep ours, report it
//   neither               →  both moved             →  conflict, keep both

export const FAST_FORWARD = 'fast-forward';
export const KEEP_LOCAL = 'keep-local';
export const ACCEPT_NEW = 'accept-new';
export const IN_SYNC = 'in-sync';
export const CONFLICT = 'conflict';
export const ROLLBACK = 'rollback';

const asMap = (x) => (x instanceof Map ? x : new Map(x.map((e) => [e.id, e])));

/**
 * @returns {{
 *   envelopes: Map, syncedRev: Map,
 *   conflicts: Array<{id, kind, local, remote}>,
 *   rolledBack: Array<{id, local, remote}>,
 *   toPush: Array<object>, actions: Map<string,string>
 * }}
 */
export function merge({ local, remote, syncedRev }) {
  const L = asMap(local);
  const R = asMap(remote);
  const base =
    syncedRev instanceof Map ? new Map(syncedRev) : new Map(Object.entries(syncedRev ?? {}));

  const envelopes = new Map(L);
  const nextSynced = new Map(base);
  const conflicts = [];
  const rolledBack = [];
  const toPush = [];
  const actions = new Map();

  for (const id of new Set([...L.keys(), ...R.keys()])) {
    const l = L.get(id);
    const r = R.get(id);
    const b = base.get(id);

    // Only on the server: something another machine created, or that this one
    // has never seen. Take it.
    if (!l && r) {
      envelopes.set(id, r);
      nextSynced.set(id, r.rev);
      actions.set(id, ACCEPT_NEW);
      continue;
    }

    // Only here — but "here and not there" is not the same as "never pushed".
    //
    // The pull is a delta: getRecords(since) returns what changed after the
    // sequence this machine last saw, so a record the server acknowledged long
    // ago is simply absent from it. Reading that absence as "not yet pushed"
    // means re-pushing every acknowledged record on every sync, for ever — a
    // quiet vault writing continuously, the global sequence climbing on every
    // poll, and every other machine pulling the same records back each time.
    // The ancestor map is what knows: if it holds exactly this revision, the
    // server has it.
    //
    // Found by the model test, from a one-operation sequence: add a record,
    // then watch it be pushed again on every sync afterwards.
    if (l && !r) {
      if (b !== undefined && b === l.rev) {
        nextSynced.set(id, l.rev);
        actions.set(id, IN_SYNC);
        continue;
      }
      // `syncedRev` advances when the server acknowledges, not now — a push
      // that fails must not look done.
      toPush.push(l);
      actions.set(id, KEEP_LOCAL);
      continue;
    }

    // Equal revision numbers do NOT imply equal content. `rev` is a per-record
    // counter incremented locally, so two machines that both edit from rev 1
    // both arrive at rev 2 — different passwords, identical numbering. Treating
    // that as "in sync" loses one of them silently, which is what happened
    // before the integration test caught it. The ciphertext is the authority.
    if (l.rev === r.rev) {
      if (l.ct === r.ct && l.n === r.n && l.deleted === r.deleted) {
        nextSynced.set(id, r.rev);
        actions.set(id, IN_SYNC);
        continue;
      }
      // Same number, different bytes: fall through to the divergence handling
      // below. Note that re-sealing identical plaintext also produces different
      // bytes, because the nonce is fresh — so two machines that happened to
      // make the same edit are reported as a conflict too. That is the safe
      // direction to be wrong in, and it is rare.
    } else {
      // A remote revision below the ancestor is not an update, it is the
      // server going backwards on a record it already acknowledged. The
      // envelope itself verifies — it really was sealed by this client at that
      // rev — which is exactly why the old fast-forward here was exploitable:
      // a server re-serving the pre-rotation envelope restored a leaked
      // password, and re-serving a pre-deletion envelope resurrected the
      // record, because the `continue` ran before the tombstone-wins logic
      // below could. Local is strictly newer, so local stays and is pushed;
      // that is the right data outcome even for a caller that looks no
      // further. But healing quietly would hide the attack, so the record is
      // named in `rolledBack` — merge is pure and cannot throw SyncError, so
      // the refusal itself (this project refuses loudly: see guardRollback in
      // sync.js) is the caller's job.
      if (b !== undefined && r.rev < b) {
        toPush.push(l);
        rolledBack.push({ id, local: l, remote: r });
        actions.set(id, ROLLBACK);
        continue;
      }
      // A fast-forward means the remote genuinely moved forward. With the
      // rollback case handled above this reduces to r.rev > b, but the rule is
      // stated in full so it cannot rot into "l.rev === b is enough" again.
      if (b !== undefined && l.rev === b && r.rev > l.rev) {
        envelopes.set(id, r);
        nextSynced.set(id, r.rev);
        actions.set(id, FAST_FORWARD);
        continue;
      }
      if (b !== undefined && r.rev === b) {
        toPush.push(l);
        actions.set(id, KEEP_LOCAL);
        continue;
      }
    }

    // Both sides moved since the ancestor — or there is no ancestor and the
    // revisions disagree, which means one was recorded and the other was not.
    // Either way this is a real divergence and is never resolved silently.
    if (l.deleted || r.deleted) {
      // A tombstone wins, so a deletion is not undone by an edit racing it.
      // The surviving edit is parked rather than dropped, so the entry can
      // still be recovered by a person who decides the deletion was the mistake.
      const tomb = l.deleted ? l : r;
      const survivor = l.deleted ? r : l;
      envelopes.set(id, tomb);
      nextSynced.set(id, r.rev);
      conflicts.push({ id, kind: 'delete', local: l, remote: r, parked: survivor });
      if (l.deleted) toPush.push(l);
    } else {
      // Local stays current so the machine in front of the user does not change
      // under them; the remote side is parked for the UI to offer as a fork.
      // Forking needs the vault key — the AAD binds id and rev — so it happens
      // after unlock, elsewhere.
      conflicts.push({ id, kind: 'edit', local: l, remote: r, parked: r });
      toPush.push(l);
    }
    actions.set(id, CONFLICT);
  }

  return { envelopes, syncedRev: nextSynced, conflicts, rolledBack, toPush, actions };
}

/** Advance the ancestor map once the server has actually accepted a push. */
export function confirmPushed(syncedRev, pushed) {
  const next = new Map(syncedRev);
  for (const e of pushed) next.set(e.id, e.rev);
  return next;
}
