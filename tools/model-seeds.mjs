// Run the sync model test across several seeds, not just the one.
//
// The default `npm test` run uses a single fixed seed and a small case count,
// and an audit measured what that costs: reintroduce the fast-forward
// resurrection guard, or the merge-layer rollback report, and the default
// configuration stays green. Both are caught within seconds once the seed
// varies. A property test pinned to one seed is a regression test wearing a
// property test's clothes.
//
//   npm run test:model              # eight seeds
//   MODEL_CASES=5000 npm run test:model
//
// Deliberately not part of `npm test`: that has to stay fast enough to run on
// every change. This is what CI runs, and what to run before a release.

import { execFileSync } from 'node:child_process';

const SEEDS = ['0xBEC0DE', '1', '31337', '5050', '987654321', '8675309', '424242', '1964435005'];
const CASES = process.env.MODEL_CASES ?? '2000';

let failed = 0;
for (const seed of SEEDS) {
  process.stdout.write(`seed ${seed} (${CASES} cases) ... `);
  try {
    execFileSync('node', ['--test', 'test/model.test.js'], {
      env: { ...process.env, MODEL_SEED: seed, MODEL_CASES: CASES },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    console.log('ok');
  } catch (err) {
    failed++;
    console.log('FAILED');
    process.stdout.write(String(err.stdout ?? '').split('\n').slice(-40).join('\n'));
  }
}

if (failed) {
  console.error(`\n${failed}/${SEEDS.length} seeds failed.`);
  process.exit(1);
}
console.log(`\nall ${SEEDS.length} seeds clean at ${CASES} cases each.`);
