// Design preview harness. Never shipped — it lives in tools/ so that no seeding
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
    name: 'Ben Ropple',
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
    name: 'Ben Ropple',
    organization: 'BENCO Holdings',
    'address-line1': '4 Phosphor Street',
    'address-level2': 'Reading',
    'postal-code': 'RG1 1AA',
    country: 'GB',
    created: now - 120 * DAY,
  },
  {
    title: 'Something imported with a bad clock',
    username: 'legacy',
    password: 'imported-value',
    created: now + 900 * DAY, // clamped on import, and reported as claimed
    timesUsed: 0,
  },
];

const q = new URLSearchParams(location.search);
const $ = (id) => document.getElementById(id);

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
  when(
    () => document.querySelector(`.seg-btn[data-section="${q.get('section')}"]`),
    () => document.querySelector(`.seg-btn[data-section="${q.get('section')}"]`).click(),
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
    },
  );
}
