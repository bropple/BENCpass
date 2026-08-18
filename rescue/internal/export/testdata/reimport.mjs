// Reads a file the Go rescue tool wrote, using the extension's own importer,
// and prints what it made of it. Driven from roundtrip_test.go.
//
//   node reimport.mjs <path>

import { readFileSync } from 'node:fs';

const core = new URL('../../../../src/core/', import.meta.url).pathname;
const { parse } = await import(core + 'transfer.js');

const records = parse(readFileSync(process.argv[2], 'utf8'), 1700000000000);
console.log(JSON.stringify(records));
