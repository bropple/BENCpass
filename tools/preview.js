// Design preview harness. Never shipped — it lives in tools/ so that no seeding

// The version the settings pane shows, handed in by preview.sh from the real
// manifest. It was a hardcoded 0.7.1 here for three releases, and was then read
// off a screenshot and believed — so it is not written down twice any more.
const MANIFEST_VERSION = globalThis.__BENCPASS_VERSION__ ?? 'dev';
// or auto-unlock code can end up inside the extension by accident.
//
// It seeds localStorage with a throwaway vault and then imports the real
// manager unchanged, so what is on screen is the actual UI rather than a mockup
// of it. Run through tools/preview.sh, which also serves the repo root — ES
// modules do not load from file:// in Firefox.

import { Vault } from '../src/core/vault.js';

const PASSWORD = 'preview-only-not-a-real-vault';
const DAY = 86_400_000;
const now = Date.now();

const SAMPLES = [
  {
    title: 'BENCO Holdings',
    username: 'ben@ropple.net',
    password: 'K7#mQp2vLx9wRt4Nz',
    urls: ['https://benco.example/login'],
    notes: 'The main one.',
    created: now - 400 * DAY,
    passwordChanged: now - 40 * DAY,
    lastUsed: now - 2 * DAY,
    timesUsed: 61,
  },
  {
    title: 'Router',
    username: 'admin',
    password: 'correct-horse-battery-staple',
    urls: ['http://192.168.1.1'],
    created: now - 1200 * DAY,
    // Deliberately ancient, to show the age indicator turning red.
    passwordChanged: now - 1180 * DAY,
    lastUsed: now - 300 * DAY,
    timesUsed: 4,
  },
  {
    title: 'Package registry',
    username: 'benco',
    password: 'shared-across-two-entries',
    urls: ['https://registry.example'],
    created: now - 700 * DAY,
    passwordChanged: now - 500 * DAY,
    timesUsed: 12,
  },
  {
    title: 'Staging box',
    username: 'deploy',
    // Same as the entry above, so the reuse warning has something to find.
    password: 'shared-across-two-entries',
    urls: ['https://staging.example'],
    created: now - 500 * DAY,
    passwordChanged: now - 500 * DAY,
    timesUsed: 3,
  },
  {
    title: 'Tailscale',
    username: 'ben@ropple.net',
    password: 'Zq4!tB8xVn1oPd6s',
    urls: ['https://login.tailscale.com'],
    created: now - 90 * DAY,
    passwordChanged: now - 90 * DAY,
    timesUsed: 8,
  },
  {
    type: 'address',
    title: 'Home',
    'given-name': 'Ben',
    'family-name': 'Ropple',
    'address-line1': '1 Pentagon Way',
    'address-level2': 'Springfield',
    'address-level1': 'Berkshire',
    'postal-code': 'RG1 4QX',
    country: 'GB',
    tel: '+44 118 496 0000',
    email: 'ben@ropple.net',
    created: now - 300 * DAY,
  },
  {
    type: 'address',
    title: 'Work',
    'honorific-prefix': 'Dr',
    'given-name': 'Ben',
    'additional-name': 'Q',
    'family-name': 'Ropple',
    organization: 'BENCO Holdings',
    'organization-title': 'Proprietor',
    'address-line1': '4 Phosphor Street',
    'address-line2': 'Floor 3',
    'address-level2': 'Reading',
    'postal-code': 'RG1 1AA',
    country: 'GB',
    'tel-extension': '204',
    created: now - 120 * DAY,
  },
  {
    // Kept in the shape the manager used to store, so the preview covers the
    // path that splits a whole name on the way to the editor.
    type: 'address',
    title: 'Old format',
    name: 'Ben Ropple',
    'address-line1': '9 Legacy Lane',
    'address-level2': 'Reading',
    'postal-code': 'RG1 2BB',
    created: now - 600 * DAY,
  },
  {
    title: 'Something imported with a bad clock',
    username: 'legacy',
    password: 'imported-value',
    created: now + 900 * DAY, // clamped on import, and reported as claimed
    timesUsed: 0,
  },
];

// Anything that goes wrong while the real manager loads, reported where it can
// be read. A module that fails to import leaves the gate as inert markup, which
// looks exactly like a wrong password.
const complain = (what) => {
  what = { where: location.search || '(no query)', ...what };
  fetch('/__result', { method: 'POST', body: JSON.stringify(what, null, 2) }).catch(() => {});
  // On screen as well as posted: a screenshot is the only output some of these
  // runs produce, and an empty gate looks the same whether the script failed to
  // load or the password was wrong.
  let box = document.getElementById('preview-complaints');
  if (!box) {
    box = document.createElement('pre');
    box.id = 'preview-complaints';
    box.style.cssText =
      'position:fixed;inset:0;z-index:99999;background:#300;color:#fdd;padding:20px;' +
      'font:12px monospace;white-space:pre-wrap;overflow:auto;margin:0';
    document.body?.append(box);
  }
  // Appended, not replaced. The first complaint is the useful one and a later
  // one drawn over the top of it hides exactly what was wanted.
  box.textContent += JSON.stringify(what, null, 2) + '\n\n';
};

for (const [event, pick] of [
  [
    'error',
    (e) => ({
      error: String(e.message),
      file: e.filename,
      line: e.lineno,
      stack: String(e.error?.stack ?? '').split('\n').slice(0, 5),
    }),
  ],
  // Firefox's .stack carries no message, so both are taken — a bare stack
  // says where and never what.
  [
    'unhandledrejection',
    (e) => ({
      error: `${e.reason?.name ?? 'Error'}: ${e.reason?.message ?? e.reason}`,
      stack: String(e.reason?.stack ?? '').split('\n').slice(0, 4),
    }),
  ],
]) {
  window.addEventListener(event, (e) => complain(pick(e)));
}

const q = new URLSearchParams(location.search);
const $ = (id) => document.getElementById(id);

// The settings panel asks the background page for everything it shows, and
// there is no background page here. Only the two messages it actually sends are
// answered — a stub of anything more would be a stub of behaviour the real
// panel does not have.
//
// `?bio=` chooses which of the three biometric states to draw, since they are
// the ones with words in them worth looking at:
//   absent   the platform could, but no host is installed  (the common case)
//   ready    a host is installed and nothing is enrolled yet
//   on       enrolled
const BIO = {
  absent: { available: false, enrolled: false, biometrics: 'none', possible: true, reason: 'no-host' },
  ready: { available: true, enrolled: false, biometrics: 'touchid', possible: true, reason: '' },
  on: { available: true, enrolled: true, biometrics: 'touchid', possible: true, reason: '' },
};

globalThis.browser = {
  runtime: {
    sendMessage: async (msg) => {
      if (msg.type === 'bio-state') return BIO[q.get('bio')] ?? BIO.absent;
      if (msg.type === 'settings-get') {
        return {
          endpoint: q.has('nosync') ? '' : 'http://192.168.1.20:8788',
          fallbackEndpoint: q.has('nosync') ? '' : 'https://bencpass.example.ts.net',
          lastSyncVia: q.has('nosync') ? '' : 'http://192.168.1.20:8788',
          autolockMinutes: 15,
          allowInsecure: false,
          deviceId: q.has('nosync') ? '' : 'workshop-mac',
          enrolled: !q.has('nosync'),
          lastSync: Date.now() - 12 * 60 * 1000,
          version: MANIFEST_VERSION,
          records: SAMPLES.length,
        };
      }
      return { ok: true };
    },
  },
};

/** Poll until the UI reaches a state, then act on it. */
const when = (ready, then) => {
  const t = setInterval(() => {
    if (!ready()) return;
    clearInterval(t);
    then();
  }, 30);
};

// ?fresh leaves storage empty so the manager shows its first-run setup gate.
localStorage.clear();
if (!q.has('fresh')) {
  const vault = await Vault.create({ password: PASSWORD });
  if (!q.has('empty')) await vault.importRecords(SAMPLES);
  localStorage.setItem('bencpass.vault', JSON.stringify(vault.toJSON()));
}

await import('../src/ui/manager.js');

setTimeout(() => {
  const mode = document.getElementById('gate')?.dataset.mode;
  if (!mode) complain({ error: 'boot() never set a gate mode — it did not finish' });
}, 1500);

// ?open drives the real unlock path rather than bypassing it, so a screenshot
// shows a vault that genuinely decrypted. ?wrong exercises the failure text.
if (q.has('open') || q.has('wrong')) {
  when(
    () => $('gate').dataset.mode === 'unlock',
    () => {
      $('gate-pw').value = q.has('wrong') ? 'not the master password' : PASSWORD;
      $('gate-form').requestSubmit();
    },
  );
}

if (q.has('section')) {
  // Waits for the app, not merely for the button: the buttons are in the static
  // markup and exist before the vault is open, so clicking on sight raced the
  // unlock and asked a locked vault for its records.
  when(
    () => !$('app').hidden && document.querySelector(`.seg-btn[data-section="${q.get('section')}"]`),
    () => document.querySelector(`.seg-btn[data-section="${q.get('section')}"]`).click(),
  );
}

if (q.has('settings')) {
  when(
    () => !$('app').hidden,
    () => $('settings-btn').click(),
  );
}

if (q.has('search')) {
  when(
    () => !$('app').hidden,
    () => {
      $('search').value = q.get('search');
      $('search').dispatchEvent(new Event('input'));
    },
  );
}

if (q.has('new')) {
  when(
    () => !$('app').hidden,
    () => {
      $('new-btn').click();
      if (q.has('gen')) $('gen-btn').click();
    },
  );
}

// select=N picks the Nth row of the sorted list, so a shot can land on the
// entry that actually exercises a given state — a stale password, a reused one,
// an import with a bad clock.
if (q.has('select')) {
  when(
    () => $('list').children.length > 0,
    () => {
      $('list').children[Number(q.get('select')) || 0].click();
      if (q.has('reveal')) $('reveal-btn').click();
      if (q.has('edit')) $('edit-btn').click();
      if (q.has('show')) $('e-reveal-btn').click();
      if (q.has('gen')) $('gen-btn').click();
      // The address editor keeps its rarely-asked-for fields behind a
      // disclosure; ?more opens it so a screenshot can show them.
      if (q.has('more')) document.querySelector('.more-fields')?.setAttribute('open', '');
    },
  );
}
