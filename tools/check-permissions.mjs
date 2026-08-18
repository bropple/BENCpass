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
      // .js only. An API can only be called from script, and the extension CSP
      // forbids inline script — so an HTML file cannot use a permission, and
      // reading them only creates a way to *fake* usage. It did: prose in a
      // page ("we used to call browser.bookmarks.getTree()") counted, because
      // stripProse removes quoted strings and comments but element text is
      // neither. Narrowing the input removes the hole rather than patching it.
    } else if (name.endsWith('.js')) {
      out.push(readFileSync(path, 'utf8'));
    }
  }
  return out;
}

/**
 * Strip comments and string literals before looking for API calls.
 *
 * Without this the check has a hole exactly where it matters: a permission
 * whose API name survives in a comment — `// we used to call browser.foo.bar()`
 * — counts as used, which is the most likely way for a name to linger after
 * the feature is gone. That is the case this tool exists to catch.
 *
 * Crude on purpose. It only has to be good enough that a mention in prose does
 * not read as a call, and being over-eager costs a false alarm rather than a
 * miss.
 */
function stripProse(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ') // block comments
    .replace(/(^|[^:])\/\/[^\n]*/g, '$1 ') // line comments, sparing "http://"
    .replace(/<!--[\s\S]*?-->/g, ' ') // html comments
    .replace(/'(?:[^'\\\n]|\\.)*'/g, "''") // string literals
    .replace(/"(?:[^"\\\n]|\\.)*"/g, '""')
    .replace(/`(?:[^`\\]|\\.)*`/g, '``');
}

// Per file, then joined. Stripping the concatenation lets an unbalanced quote
// in one file swallow the start of the next — which it did: `idle` came back
// unused because something earlier ate the line that calls it.
const code = sources(join(root, 'src')).map(stripProse).join('\n');

/**
 * What using a permission looks like.
 *
 * Most are a namespace on `browser`, so the default rule covers them and a new
 * permission needs no entry here. The exceptions are the ones whose API is not
 * named after them.
 */
// Word-bounded, all of them. Without a left boundary `browser.bookmarks.` also
// matches `mybrowser.bookmarks.`, and `connectNative` matches inside
// `reconnectNativeThing` — both demonstrated hiding an unused permission behind
// a name that merely ends the right way.
//
// Word characters only, not a preceding dot: every reach for an API here is
// written `globalThis.browser?.…`, so excluding `.` rejects the real calls and
// reports the whole extension as using nothing.
const SPECIAL = {
  nativeMessaging: /\b(?:connectNative|sendNativeMessage)\b/,
  idle: /(?<![\w$])browser\??\.idle\??\./,
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
  // `browser?.storage?.local` is a call too. Optional chaining is how every
  // reach for an API that may be absent is written here, so a rule demanding
  // plain dots matches none of them — and the check passed anyway, because the
  // comments beside those calls spell the API out. Two holes cancelling out.
  const rule = SPECIAL[p] ?? new RegExp(`(?<![\\w$])browser\\??\\.${p}\\??\\.`);
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
