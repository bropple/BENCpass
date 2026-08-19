// Regenerate the country table inside src/core/address.js.
//
//   node tools/gen-countries.mjs          rewrite the table
//   node tools/gen-countries.mjs --check   fail if it is out of date
//
// The names come from ICU, which ships with Node, rather than from a list typed
// out by hand — 267 country names is 267 chances to make a typo that nobody
// notices until a checkout in that country silently fails to fill.
//
// Regions CLDR knows about that are not ISO 3166-1 countries are dropped: the
// EU and the eurozone, the UN, the "unknown region" placeholder, and the
// user-assigned codes CLDR uses for the Canaries, Ceuta and Melilla and the
// like. A country <select> never offers them.

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

const NOT_COUNTRIES = new Set([
  // Groupings and placeholders.
  'EU', 'EZ', 'UN', 'QO', 'XA', 'XB', 'XK',
  // Exceptional and user-assigned reservations CLDR carries.
  'AC', 'CP', 'DG', 'EA', 'IC', 'TA',
  // Withdrawn from ISO 3166-1. ICU still resolves them, so a country <select>
  // built this year will not have them and a record holding one would never
  // match. AN split into BQ/CW/SX in 2010; the rest are older still.
  'AN', 'BU', 'CS', 'DD', 'FX', 'NT', 'SU', 'TP', 'YD', 'YU', 'ZR',
  // Aliases: a second code ICU resolves to a country that already has one.
  // UK is reserved rather than assigned — GB is the code — and the others are
  // the pre-independence or pre-unification names. Left in, each would give
  // its country a second entry, and the name-to-code map would resolve
  // "United Kingdom" to whichever was inserted last. The duplicate check
  // below is what stops a new one slipping in unnoticed.
  'UK', 'HV', 'DY', 'NH', 'RH', 'VD',
]);

const display = new Intl.DisplayNames(['en'], { type: 'region' });
const letters = [...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'];
const entries = [];

for (const a of letters) {
  for (const b of letters) {
    const code = a + b;
    if (NOT_COUNTRIES.has(code)) continue;
    let name;
    try {
      name = display.of(code);
    } catch {
      continue;
    }
    // An unknown region comes back as the code it was given.
    if (!name || name === code) continue;
    if (name.includes('|') || name.includes(':')) {
      throw new Error(`${code} (${name}) would break the table's separators`);
    }
    entries.push(`${code}:${name}`);
  }
}

if (entries.length < 240) throw new Error(`only ${entries.length} regions — is ICU complete?`);

// Two codes with one name means one of them is an alias, and a name that maps
// to two codes cannot be resolved back to either with any confidence. Fail
// rather than emit it: a future ICU that revives an old code should stop this
// script, not quietly make `countryCode('United Kingdom')` answer `UK`.
const byName = new Map();
for (const entry of entries) {
  const [code, name] = [entry.slice(0, 2), entry.slice(3)];
  if (byName.has(name)) {
    throw new Error(`${name} is both ${byName.get(name)} and ${code} — add one to NOT_COUNTRIES`);
  }
  byName.set(name, code);
}

const here = path.dirname(fileURLToPath(import.meta.url));
const target = path.join(here, '..', 'src', 'core', 'address.js');
const source = readFileSync(target, 'utf8');

// Wrapped, because one 3.6 kB line is unreviewable in a diff.
const wrapped = [];
let line = '';
for (const entry of entries) {
  const next = line ? `${line}|${entry}` : entry;
  if (next.length > 88 && line) {
    wrapped.push(line);
    line = entry;
  } else {
    line = next;
  }
}
wrapped.push(line);

const block =
  'const COUNTRY_TABLE =\n' +
  // Backslash first, then quote. Escaping the quote alone means a name
  // containing a backslash emits `\'` as an escaped quote rather than an
  // escaped backslash, and the generated line stops being the string it was
  // meant to be — in a file that ships. No country name contains one today,
  // which is exactly why this would have been found late.
  wrapped.map((l, i) => `  '${i ? '|' : ''}${l.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`).join(' +\n') +
  ';';

// Matched before it is replaced, so that "the table is already correct" and
// "there is no table here any more" stay distinguishable — a --check that
// cannot find the assignment must fail loudly rather than report success.
const ASSIGNMENT = /const COUNTRY_TABLE =[\s\S]*?;\n/;
if (!ASSIGNMENT.test(source)) throw new Error('no COUNTRY_TABLE assignment found in address.js');
const replaced = source.replace(ASSIGNMENT, `${block}\n`);

if (process.argv.includes('--check')) {
  if (replaced !== source) {
    console.error('src/core/address.js country table is out of date — run tools/gen-countries.mjs');
    process.exit(1);
  }
  console.log(`country table up to date (${entries.length} countries)`);
} else {
  writeFileSync(target, replaced);
  console.log(`wrote ${entries.length} countries into src/core/address.js`);
}
