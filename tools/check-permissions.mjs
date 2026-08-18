// Does the manifest ask for anything the code does not use?
//
// A permission outliving its feature is easy to create and invisible
// afterwards: nothing breaks, no test fails, and the extension quietly keeps
// asking for a capability nobody needs. `nativeMessaging` survived the removal
// of the native host that way — the right to start a program outside the
// browser, requested by a password manager, used by nothing.
//
// For anyone reading a password manager's manifest, an unused permission is
// not untidiness. It is the first thing they will notice and the least
// charitable thing they can conclude.
//
//   node tools/check-permissions.mjs

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const manifest = JSON.parse(readFileSync(join(root, 'src/manifest.json'), 'utf8'));

/** Every .js and .html under src/, minus vendored code we do not own. */
function sources(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name !== 'vendor') sources(path, out);
    } else if (name.endsWith('.js') || name.endsWith('.html')) {
      out.push(readFileSync(path, 'utf8'));
    }
  }
  return out;
}

const code = sources(join(root, 'src')).join('\n');

/**
 * What using a permission looks like.
 *
 * Most are a namespace on `browser`, so the default rule covers them and a new
 * permission needs no entry here. The exceptions are the ones whose API is not
 * named after them.
 */
const SPECIAL = {
  nativeMessaging: /connectNative|sendNativeMessage/,
  clipboardWrite: /navigator\.clipboard|execCommand\(\s*['"]copy/,
  activeTab: /browser\.tabs\./,
  // Host permissions are not APIs. They are matched by pattern below and are
  // used by the content script's `matches`, which the manifest declares rather
  // than the code calling.
};

// Anything that looks like a match pattern rather than an API name.
const isHostPermission = (p) => p.includes('://') || p === '<all_urls>';

const unused = [];
for (const p of manifest.permissions ?? []) {
  if (isHostPermission(p)) continue;
  const rule = SPECIAL[p] ?? new RegExp(`browser\\.${p}\\.`);
  if (!rule.test(code)) unused.push(p);
}

if (unused.length) {
  console.error(
    `manifest.json asks for ${unused.length} permission(s) nothing uses:\n` +
      unused.map((p) => `  ${p}`).join('\n') +
      '\n\nRemove them, or add the call that needs them.',
  );
  process.exit(1);
}

console.log(`every requested permission is used (${(manifest.permissions ?? []).length} checked)`);
