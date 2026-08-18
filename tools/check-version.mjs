// One version, in more than one file, agreeing.
//
// They did not: the manifest said 0.10.3 while package.json said 0.1.0, having
// drifted for most of the project's life. The manifest is the one that matters
// — it is what a user sees and what Firefox orders updates by — so a wrong
// number elsewhere is invisible right up until it is the number a release is
// cut from.
//
//   node tools/check-version.mjs
//   node tools/check-version.mjs 0.12.0    set both to this

import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const files = ['src/manifest.json', 'package.json'];

const wanted = process.argv[2];
if (wanted && !/^\d+\.\d+\.\d+$/.test(wanted)) {
  console.error(`not a version: ${wanted}`);
  process.exit(1);
}

if (wanted) {
  for (const f of files) {
    const path = join(root, f);
    const text = readFileSync(path, 'utf8').replace(/"version":\s*"[^"]+"/, `"version": "${wanted}"`);
    writeFileSync(path, text);
  }
  console.log(`set to ${wanted} in ${files.join(', ')}`);
  process.exit(0);
}

const seen = files.map((f) => [f, JSON.parse(readFileSync(join(root, f), 'utf8')).version]);
const [, first] = seen[0];
const disagree = seen.filter(([, v]) => v !== first);

if (disagree.length) {
  console.error('these disagree about the version:');
  for (const [f, v] of seen) console.error(`  ${v}\t${f}`);
  console.error('\nRun: node tools/check-version.mjs <version>');
  process.exit(1);
}
console.log(`version ${first}, agreed by ${files.length} files`);
