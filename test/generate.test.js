import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generate, randomInt, entropyBits, SETS, AMBIGUOUS } from '../src/core/generate.js';

test('generated passwords have the requested length', () => {
  for (const length of [8, 20, 64, 128]) {
    assert.equal(generate({ length }).length, length);
  }
});

test('every requested character class appears', () => {
  // 200 draws at the shortest length that can hold all four classes — the case
  // where a naive generator most often omits one.
  for (let i = 0; i < 200; i++) {
    const p = generate({ length: 4 });
    for (const set of Object.values(SETS)) {
      assert.ok([...p].some((c) => set.includes(c)), `missing a class in ${p}`);
    }
  }
});

test('unselected classes never appear', () => {
  for (let i = 0; i < 100; i++) {
    const p = generate({ length: 30, symbols: false, digits: false });
    assert.match(p, /^[a-zA-Z]+$/);
  }
});

test('ambiguous characters are excluded on request', () => {
  for (let i = 0; i < 100; i++) {
    for (const c of generate({ length: 40, avoidAmbiguous: true })) {
      assert.equal(AMBIGUOUS.includes(c), false, `${c} should have been excluded`);
    }
  }
});

test('impossible requests fail loudly rather than quietly weakening', () => {
  assert.throws(() => generate({ length: 3 }), /cannot contain 4 required classes/);
  assert.throws(
    () => generate({ lower: false, upper: false, digits: false, symbols: false }),
    /at least one character set/,
  );
});

test('randomInt stays in range', () => {
  for (let i = 0; i < 5000; i++) {
    const n = randomInt(7);
    assert.ok(n >= 0 && n < 7);
  }
  assert.equal(randomInt(1), 0);
});

test('randomInt rejects a range it cannot serve', () => {
  for (const bad of [0, -1, 1.5, 2 ** 32 + 1, NaN]) {
    assert.throws(() => randomInt(bad), RangeError);
  }
});

test('randomInt is not biased toward the low residues', () => {
  // The failure this guards against is `% max`, which over-weights the first
  // (2^32 mod max) values. With max = 100 the skew is far too small to see
  // here — so this uses a range where modulo would be blatant, and checks the
  // shape rather than trying to be a real statistical test.
  const MAX = 3;
  const N = 60_000;
  const counts = new Array(MAX).fill(0);
  for (let i = 0; i < N; i++) counts[randomInt(MAX)]++;

  const expected = N / MAX;
  for (const c of counts) {
    // ±4% at n=60000 is roughly six standard deviations; a real bias would be
    // a persistent lean in one direction rather than a near-miss.
    assert.ok(
      Math.abs(c - expected) / expected < 0.04,
      `distribution is lopsided: ${counts.join(', ')}`,
    );
  }
});

test('successive passwords differ', () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) seen.add(generate({ length: 20 }));
  assert.equal(seen.size, 500);
});

test('entropy is reported for the process, not the string', () => {
  // 26+26+10+28 = 90 characters, log2(90) ≈ 6.492 bits each.
  assert.ok(Math.abs(entropyBits({ length: 20 }) - 20 * Math.log2(90)) < 1e-9);
  // Fewer classes, less entropy per character.
  assert.ok(entropyBits({ length: 20, symbols: false }) < entropyBits({ length: 20 }));
  // Excluding ambiguous characters costs entropy, which is why it is opt-in.
  assert.ok(
    entropyBits({ length: 20, avoidAmbiguous: true }) < entropyBits({ length: 20 }),
  );
});
