// How a list of records is ordered, and which of them share a password.
//
// Here rather than in the manager because both are decisions rather than
// drawing, and a decision that cannot be tested without a browser is a decision
// nobody tests. The manager does the rendering; this answers what to render and
// in what order.

import { LOGIN } from './model.js';

/**
 * The orderings, and a title tiebreak under each of them.
 *
 * Without the tiebreak, every entry that shares a date — which after an import
 * is all of them — comes back in whatever order the map happened to hold, and
 * that order changes between redraws. A list that reshuffles while being read
 * is worse than one sorted the wrong way.
 *
 * Missing dates sort as 0 rather than being dropped: an address has no
 * passwordChanged and an entry never used has no lastUsed, and both still have
 * to appear somewhere.
 */
export const byTitle = (a, b) => (a.title || '').localeCompare(b.title || '');
const then = (cmp) => (a, b) => cmp(a, b) || byTitle(a, b);

export const ORDER = {
  title: byTitle,
  added: then((a, b) => (b.created ?? 0) - (a.created ?? 0)),
  oldest: then((a, b) => (a.created ?? 0) - (b.created ?? 0)),
  stale: then((a, b) => (a.passwordChanged ?? 0) - (b.passwordChanged ?? 0)),
  used: then((a, b) => (b.lastUsed ?? 0) - (a.lastUsed ?? 0)),
};

/**
 * Which passwords are on more than one entry.
 *
 * Reuse is a property of a pair, so no amount of looking at one entry reveals
 * it — this is the only thing in the program that can answer "where else did I
 * use this". Returns id -> the OTHER records sharing that password, and only
 * for the ids that share with somebody.
 *
 * One definition, used by both the list and the detail pane. They each had
 * their own before, which is two chances to disagree about what "reused" means
 * — and they already did: one counted addresses and the other did not.
 *
 * Keyed by the password itself, which is a plaintext map held for the length of
 * one redraw. That is not a new exposure: an unlocked vault already holds every
 * one of these in memory, and the alternative — hashing 534 passwords through
 * SubtleCrypto — is async, slower, and buys nothing against an attacker who can
 * already read the vault. It is never persisted and never rendered.
 */
export function reuseGroups(records) {
  const groups = new Map();
  for (const r of records) {
    if (r.type !== LOGIN || !r.password) continue;
    const seen = groups.get(r.password);
    if (seen) seen.push(r);
    else groups.set(r.password, [r]);
  }

  const shared = new Map();
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    for (const r of group) shared.set(r.id, group.filter((o) => o.id !== r.id));
  }
  return shared;
}

/** The same question, answered as "how many entries in total". */
export function reuseCounts(records) {
  const counts = new Map();
  for (const [id, others] of reuseGroups(records)) counts.set(id, others.length + 1);
  return counts;
}
