// The way back in when the master password is gone.
//
// Forgetting it is otherwise final, and finality is the correct default: a
// vault with a back door is a vault with a back door. So this is not a reset,
// and nothing here can be done by someone who does not already hold the code.
//
// The code is a second secret, generated once, shown once, and never stored.
// It wraps the vault key exactly as the master password does — a third
// independent wrapping beside the password and the fingerprint — so producing
// it is the same act as knowing the password, and losing it costs nothing.
//
// It is meant to be printed and put somewhere physical. That is the whole
// design: a secret that is useless to anyone on the network and safe from
// everything except somebody in your house.

import { randomInt } from './generate.js';

/**
 * The alphabet a recovery code is written in.
 *
 * No 0/O, no 1/I/l. Someone is going to read this off paper, possibly years
 * later, possibly in bad light, and every ambiguous pair is a chance to be
 * locked out while holding the answer. Upper case for the same reason: mixed
 * case on paper is another thing to get wrong.
 */
export const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

/** Characters per group, and groups per code. 30 characters, ~147 bits. */
const GROUP = 5;
const GROUPS = 6;

/**
 * A fresh recovery code, formatted for paper.
 *
 * Grouped with dashes because a thirty-character run is unreadable and
 * untypable; the dashes are presentation only and `normalise` removes them.
 */
export function newRecoveryCode() {
  const groups = [];
  for (let g = 0; g < GROUPS; g++) {
    let group = '';
    for (let i = 0; i < GROUP; i++) group += ALPHABET[randomInt(ALPHABET.length)];
    groups.push(group);
  }
  return groups.join('-');
}

/**
 * What was typed, reduced to what was meant.
 *
 * Case, spacing and dashes are all presentation. Someone copying from paper
 * will lower-case it, or paste it with a line break in the middle, and none of
 * that should decide whether a vault comes back.
 *
 * Anything outside the alphabet is dropped rather than guessed at. There is no
 * sensible mapping for a misread character: the alphabet has no O, I, L, 0 or 1
 * precisely so that no code can contain one, which means seeing one tells you
 * the reader mistook some *other* character — and inventing a substitution
 * would turn a wrong code into a differently wrong code that fails just the
 * same, having also disguised where the mistake was.
 *
 * The filter is built from the alphabet itself, so the two cannot drift. An
 * earlier version mapped O to 0 and I to 1 by hand, which was nonsense in both
 * directions — neither 0 nor 1 is a legal character — and a round trip of a
 * generated code, which contains none of them, passed anyway.
 */
export function normalise(code) {
  const allowed = new Set(ALPHABET);
  return [...String(code ?? '').toUpperCase()].filter((c) => allowed.has(c)).join('');
}

/** How many characters a well-formed code has, ignoring the dashes. */
export const CODE_LENGTH = GROUP * GROUPS;

/** Roughly how much entropy one carries, for anything that wants to say so. */
export const CODE_BITS = Math.floor(CODE_LENGTH * Math.log2(ALPHABET.length));
