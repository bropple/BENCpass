// Fixtures for the Go rescue tool, written by the real JavaScript core.
//
// The rescue tool is a second implementation of the vault format, in another
// language, and the whole point of it is to be reachable on the day the first
// one is not. Two implementations of one format drift — quietly, and in the
// direction nobody is looking, because the tool that has to work is the one
// nobody exercises until it matters.
//
// So the Go side is not tested against constants a Go programmer typed. It is
// tested against bytes this file produced by running the shipping code, and
// against the plaintext that code says is inside them. If Argon2's parameters,
// the AAD strings, the base64, the tombstone rule or the record shape move on
// either side, the Go tests fail.
//
// Regenerate after any change to the vault format:
//
//   node rescue/internal/vault/testdata/gen.mjs

import { writeFileSync } from 'node:fs';

const core = new URL('../../../../src/core/', import.meta.url).pathname;
const { Vault } = await import(core + 'vault.js');

// Fixed, so the fixtures are reproducible and a diff means something changed.
const PASSWORD = 'correct horse battery staple';
const CODE = 'ABCDE-FGHJK-MNPQR-STUVW-XYZ23-45678';
const T = 1700000000000;

const v = await Vault.create({ password: PASSWORD, now: T });

await v.add(
  { type: 'login', title: 'Example', username: 'ben', password: 'hunter2',
    urls: ['https://example.com'], notes: 'a note' }, T);

// Everything awkward, in one record: non-ASCII in three scripts, and the four
// characters a CSV writer has to think about.
await v.add(
  { type: 'login', title: 'Ünïcødé ✓ 日本', username: 'ben@ropple.net',
    password: 'p\ttab "quote" ,comma\\back', urls: ['https://a.example', 'https://b.example'],
    notes: 'line one\nline two' }, T + 1);

await v.add(
  { type: 'address', title: 'Home', 'name': 'Ben Ropple',
    'address-line1': '1 Example Road', 'address-level2': 'Springfield',
    'postal-code': '12345', 'country': 'US', 'tel': '+1 555 0100',
    'email': 'ben@ropple.net' }, T + 2);

// A tombstone. The Go side must not list it, and must decide that by opening
// the sealed body rather than by believing the cleartext `deleted` flag.
const doomed = await v.add(
  { type: 'login', title: 'Deleted', username: 'x', password: 'y' }, T + 3);
await v.remove(doomed, T + 4);

await v.enrolRecovery(PASSWORD, CODE, T);

const persisted = v.toJSON();

// 1. What the extension's "save an encrypted backup" writes.
writeFileSync(new URL('./backup.json', import.meta.url),
  JSON.stringify(persisted, null, 2) + '\n');

// 2. What the server keeps in its data directory. Same vault, different shape:
// records keyed by id and carrying a sequence number, beside devices and codes
// the rescue tool has no business reading.
const records = {};
let seq = 0;
for (const e of persisted.envelopes) records[e.id] = { ...e, seq: ++seq };
writeFileSync(new URL('./store.json', import.meta.url),
  JSON.stringify({ seq, meta: persisted.meta, records, devices: {}, codes: {} }, null, 2) + '\n');

// 3. The truth: what is actually inside, according to the code that sealed it.
writeFileSync(new URL('./expected.json', import.meta.url),
  JSON.stringify({ password: PASSWORD, code: CODE, tombstone: doomed,
                   records: v.list() }, null, 2) + '\n');

console.log(`${persisted.envelopes.length} envelopes, ${v.list().length} live, tombstone ${doomed}`);
