// Password generation.
//
// Small, but the place a subtle bias hides, so it gets its own file and its own
// tests rather than being three lines inside a UI handler.

export const SETS = Object.freeze({
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!#$%&()*+,-./:;<=>?@[]^_{|}~',
});

// Characters that are indistinguishable in the fonts this project uses, and in
// most others. Excluded on request rather than by default, since removing them
// costs entropy and only matters for a password someone has to read aloud or
// retype from a screen.
export const AMBIGUOUS = 'Il1O0oS5B8|';

/**
 * A uniform integer in [0, max).
 *
 * Rejection sampling, not `% max`. Modulo over a 32-bit draw makes the low
 * residues more likely whenever max does not divide 2^32 — with a 72-character
 * pool that is a real, measurable skew toward the front of the alphabet, and it
 * is invisible in any output you would eyeball.
 */
export function randomInt(max) {
  if (!Number.isInteger(max) || max <= 0 || max > 2 ** 32) {
    throw new RangeError(`max out of range: ${max}`);
  }
  const limit = Math.floor(2 ** 32 / max) * max;
  const buf = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return x % max;
}

function draw(pool, length) {
  let out = '';
  for (let i = 0; i < length; i++) out += pool[randomInt(pool.length)];
  return out;
}

/**
 * Generate a password.
 *
 * When classes are required, the whole candidate is redrawn until it satisfies
 * them, rather than patching characters into fixed positions afterwards. The
 * patching approach is the common one and it biases those positions; redrawing
 * keeps the distribution uniform over the set of valid passwords. At sane
 * lengths it almost never loops more than once.
 */
export function generate({
  length = 20,
  lower = true,
  upper = true,
  digits = true,
  symbols = true,
  avoidAmbiguous = false,
} = {}) {
  const chosen = { lower, upper, digits, symbols };
  const active = Object.keys(SETS).filter((k) => chosen[k]);
  if (active.length === 0) throw new Error('at least one character set is required');
  if (length < active.length) {
    throw new Error(`length ${length} cannot contain ${active.length} required classes`);
  }

  const filter = (s) =>
    avoidAmbiguous
      ? [...s].filter((c) => !AMBIGUOUS.includes(c)).join('')
      : s;

  const sets = active.map((k) => filter(SETS[k]));
  if (sets.some((s) => s.length === 0)) {
    throw new Error('a required character set is empty after excluding ambiguous characters');
  }
  const pool = sets.join('');

  for (let attempt = 0; attempt < 1000; attempt++) {
    const candidate = draw(pool, length);
    if (sets.every((s) => [...candidate].some((c) => s.includes(c)))) return candidate;
  }
  // Unreachable for any sane input; a loud failure beats a silently weak one.
  throw new Error('could not satisfy the required character classes');
}

/** Shannon entropy of the generating process, in bits — not of the string itself. */
export function entropyBits({ length = 20, ...opts } = {}) {
  const chosen = { lower: true, upper: true, digits: true, symbols: true, ...opts };
  const active = Object.keys(SETS).filter((k) => chosen[k]);
  const filter = (s) =>
    opts.avoidAmbiguous ? [...s].filter((c) => !AMBIGUOUS.includes(c)).join('') : s;
  const poolSize = active.reduce((n, k) => n + filter(SETS[k]).length, 0);
  return length * Math.log2(poolSize);
}
