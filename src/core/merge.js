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
//   neither               →  both moved             →  conflict, keep both

export const FAST_FORWARD = 'fast-forward';
export const KEEP_LOCAL = 'keep-local';
export const ACCEPT_NEW = 'accept-new';
export const IN_SYNC = 'in-sync';
export const CONFLICT = 'conflict';

const asMap = (x) => (x instanceof Map ? x : new Map(x.map((e) => [e.id, e])));

/**
 * @returns {{
 *   envelopes: Map, syncedRev: Map,
 *   conflicts: Array<{id, kind, local, remote}>,
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

    // Only here: created locally and not yet pushed. `syncedRev` advances when
    // the server acknowledges, not now — a push that fails must not look done.
    if (l && !r) {
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
      if (b !== undefined && l.rev === b) {
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

  return { envelopes, syncedRev: nextSynced, conflicts, toPush, actions };
}

/** Advance the ancestor map once the server has actually accepted a push. */
export function confirmPushed(syncedRev, pushed) {
  const next = new Map(syncedRev);
  for (const e of pushed) next.set(e.id, e.rev);
  return next;
}
