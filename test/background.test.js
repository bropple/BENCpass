// The background page's vault-lifecycle handlers, run under Node against a
// fake `browser`.
//
// Two shipped defects live here and each nearly cost a vault:
//
//  1. First-run setup built the Vault in the MANAGER document and handed the
//     instance to the background, which kept it. Firefox nukes a closed
//     document's compartment, so the background was left holding a dead-object
//     wrapper: the badge repaint on tabs.onRemoved hit `vault.locked` and threw
//     "can't access dead object", permanently, until the background restarted.
//  2. boot() reads storage asynchronously, and both the message handlers and
//     the manager read the in-memory `vault` before that read landed: a
//     machine holding 534 records reported "no vault", the manager painted the
//     SETUP gate, and a password typed there would have persisted an empty
//     vault over the real one.
//
// Node cannot observe the dead object itself — compartment nuking is a Firefox
// behaviour, reproduced separately in a real browser. What Node CAN pin, and
// does here: the background builds the vault itself from a password that
// crosses as a string (no instance ever crosses; setVault is gone), no message
// is answered before boot has read storage, and creating or joining refuses to
// overwrite a vault that is already in storage even when the in-memory
// variable is blank.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Vault } from '../src/core/vault.js';
import { MSG } from '../src/ext/protocol.js';

const FAST = { name: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 };

// The background arms real timers — a 15-minute auto-lock, a 5-minute sync
// interval — and Node would sit waiting for them after the tests finish.
// Unref'd they still fire on schedule; they just cannot hold the process open.
// Short timeouts keep their ref so the tests' own awaits are undisturbed.
const realSetTimeout = globalThis.setTimeout;
const realSetInterval = globalThis.setInterval;
globalThis.setTimeout = (fn, ms, ...args) => {
  const t = realSetTimeout(fn, ms, ...args);
  if (ms > 60_000) t.unref?.();
  return t;
};
globalThis.setInterval = (fn, ms, ...args) => {
  const t = realSetInterval(fn, ms, ...args);
  t.unref?.();
  return t;
};

const sleep = (ms) => new Promise((r) => realSetTimeout(r, ms));

/** The message sender the background sees when its own manager page asks. */
const MANAGER = { url: 'moz-extension://test/ui/manager.html', tab: { id: 7 } };

/**
 * Just enough `browser` for background.js to load and answer messages. Every
 * stub is the quietest honest answer: no tabs, no notifications, no idle API,
 * no host permission. `delayVaultRead` holds the boot-time vault read open so
 * a test can stand inside the window where memory and storage disagree.
 */
function fakeBrowser({ storage = {}, delayVaultRead = null } = {}) {
  const data = new Map(Object.entries(storage));
  const listeners = {};
  let vaultReads = 0;

  const local = {
    async get(key) {
      if (key === 'bencpass.vault' && delayVaultRead && vaultReads++ === 0) await delayVaultRead;
      return data.has(key) ? { [key]: structuredClone(data.get(key)) } : {};
    },
    async set(obj) {
      for (const [k, v] of Object.entries(obj)) data.set(k, structuredClone(v));
    },
    async remove(key) {
      data.delete(key);
    },
  };

  const browser = {
    storage: { local },
    runtime: {
      id: 'test',
      getURL: (p = '') => `moz-extension://test/${p}`,
      getManifest: () => ({ version: '0.0.0-test' }),
      getPlatformInfo: async () => ({ os: 'linux' }),
      sendMessage: async () => undefined,
      onMessage: { addListener: (fn) => (listeners.message = fn) },
    },
    tabs: {
      onRemoved: { addListener: (fn) => (listeners.tabRemoved = fn) },
      query: async () => [],
      sendMessage: async () => undefined,
      create: async () => ({ id: 1 }),
      update: async () => ({}),
      remove: async () => undefined,
    },
    menus: { create: () => {}, onClicked: { addListener: () => {} } },
    commands: { onCommand: { addListener: () => {} } },
    notifications: { onClicked: { addListener: () => {} } },
    browserAction: {
      setBadgeText: () => {},
      setBadgeBackgroundColor: () => {},
      setIcon: () => Promise.resolve(),
    },
    idle: { setDetectionInterval: () => {}, onStateChanged: { addListener: () => {} } },
    permissions: { contains: async () => false },
    windows: { update: async () => ({}) },
  };

  return { browser, data, listeners };
}

// background.js keeps module state (the vault, the settings), so every
// scenario needs its own copy. A query string is a different module URL to
// Node, which is the supported way to load one file twice.
let realm = 0;
async function loadBackground(fake) {
  globalThis.browser = fake.browser;
  globalThis.window = globalThis;
  await import(`../src/ext/background.js?realm=${realm++}`);
  const bencpass = globalThis.window.bencpass;
  return {
    bencpass,
    send: (msg, sender = MANAGER) => fake.listeners.message(msg, sender),
    tabClosed: (tabId) => fake.listeners.tabRemoved(tabId),
  };
}

test('SETUP builds the vault in the background and persists it', async () => {
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);

  const reply = await bg.send({ type: MSG.SETUP, password: 'correct horse' });
  assert.equal(reply.ok, true);

  // The background holds it, unlocked, and storage holds a copy that the same
  // password opens — proof the persisted bytes are the vault, not a husk.
  assert.equal(bg.bencpass.vault.locked, false);
  const stored = fake.data.get('bencpass.vault');
  assert.ok(stored, 'nothing was persisted');
  await Vault.load(stored).unlock('correct horse');

  // The instance never crosses a realm in either direction any more: the one
  // way a page could hand a vault in is gone. This assertion is the tripwire
  // against it quietly coming back.
  assert.equal(bg.bencpass.setVault, undefined);

  // The crash site itself: a tab closing repaints the badge, which reads
  // vault.locked. With the vault built here it must simply work.
  bg.tabClosed(3);
  assert.equal(bg.bencpass.vault.locked, false);
});

test('SETUP round-trips with LOCK and UNLOCK like any other vault', async () => {
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);

  await bg.send({ type: MSG.SETUP, password: 'correct horse' });
  await bg.send({ type: MSG.LOCK });
  assert.equal(bg.bencpass.vault.locked, true);

  const wrong = await bg.send({ type: MSG.UNLOCK, password: 'wrong horse' });
  assert.equal(wrong.ok, false);

  const right = await bg.send({ type: MSG.UNLOCK, password: 'correct horse' });
  assert.equal(right.ok, true);
  assert.equal(bg.bencpass.vault.locked, false);
});

test('SETUP refuses a second vault, and refuses an empty password', async () => {
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);

  const empty = await bg.send({ type: MSG.SETUP, password: '' });
  assert.equal(empty.ok, false);
  assert.equal(empty.reason, 'no-password');

  await bg.send({ type: MSG.SETUP, password: 'correct horse' });
  const again = await bg.send({ type: MSG.SETUP, password: 'another horse' });
  assert.equal(again.ok, false);
  assert.equal(again.reason, 'already-a-vault');
});

test('SETUP consults storage, not memory: a vault the background has not seen still refuses the overwrite', async () => {
  // The dangerous window: storage holds a vault, the in-memory variable is
  // blank. boot() in flight is one way there; a failed boot is another. Modelled
  // by booting empty and then planting the vault behind the background's back.
  const existing = (await Vault.create({ password: 'the real one', kdf: FAST })).toJSON();
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);
  await bg.send({ type: MSG.STATE }); // ensure boot has finished on an empty store
  fake.data.set('bencpass.vault', existing);

  const reply = await bg.send({ type: MSG.SETUP, password: 'a fresh empty vault' });
  assert.equal(reply.ok, false);
  assert.equal(reply.reason, 'already-a-vault');
  assert.deepEqual(fake.data.get('bencpass.vault'), existing, 'the stored vault was touched');
});

test('JOIN makes the same refusal from the same evidence', async () => {
  const existing = (await Vault.create({ password: 'the real one', kdf: FAST })).toJSON();
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);
  await bg.send({ type: MSG.STATE });
  fake.data.set('bencpass.vault', existing);

  const reply = await bg.send({ type: MSG.JOIN, password: 'whatever' });
  assert.equal(reply.ok, false);
  assert.equal(reply.reason, 'already-a-vault');
  assert.deepEqual(fake.data.get('bencpass.vault'), existing);
});

test('no message is answered before boot has read storage', async () => {
  // The boot race as reported: the browser restarts, the manager asks for
  // state while boot()'s storage read is still in flight, and the old code
  // answered hasVault:false off the blank variable — which is what painted a
  // setup gate on a machine holding 534 records.
  const existing = (await Vault.create({ password: 'the real one', kdf: FAST })).toJSON();
  let release;
  const gate = new Promise((r) => (release = r));
  const fake = fakeBrowser({
    storage: { 'bencpass.vault': existing },
    delayVaultRead: gate,
  });
  const bg = await loadBackground(fake);

  const asking = bg.send({ type: MSG.STATE });
  const early = await Promise.race([asking, sleep(50).then(() => 'unanswered')]);
  assert.equal(early, 'unanswered', 'a reply went out before boot finished');

  release();
  const state = await asking;
  assert.equal(state.hasVault, true);
  assert.equal(state.locked, true);

  // And SETUP inside the same window: held until boot lands, then refused.
  const madeDuringBoot = await bg.send({ type: MSG.SETUP, password: 'overwriter' });
  assert.equal(madeDuringBoot.ok, false);
  assert.equal(madeDuringBoot.reason, 'already-a-vault');
  assert.deepEqual(fake.data.get('bencpass.vault'), existing);
});

test('the readiness promise the manager awaits settles with boot', async () => {
  const existing = (await Vault.create({ password: 'the real one', kdf: FAST })).toJSON();
  let release;
  const gate = new Promise((r) => (release = r));
  const fake = fakeBrowser({ storage: { 'bencpass.vault': existing }, delayVaultRead: gate });
  const bg = await loadBackground(fake);

  // Before boot lands the vault reads as absent — exactly the null the manager
  // used to mistake for "offer setup". ready is what makes waiting possible.
  assert.equal(bg.bencpass.vault, null);
  let settled = false;
  bg.bencpass.ready.then(() => (settled = true));
  await sleep(20);
  assert.equal(settled, false, 'ready settled before storage was read');

  release();
  await bg.bencpass.ready;
  assert.ok(bg.bencpass.vault, 'boot finished without loading the stored vault');
  assert.equal(bg.bencpass.vault.locked, true);
});

// ---- captures ---------------------------------------------------------------
//
// The capture path is deliberately forgiving — a missed save loses a password
// the person just chose — but forgiving is not the same as credulous, and
// these pin the two places it declines.

/** The sender a content script has: the page's own URL, a real tab. */
const PAGE = (url, tabId = 5) => ({ url, tab: { id: tabId, url }, frameId: 0 });

test('a bare-digit username is not offered for saving', async () => {
  // Seen in real use on the TrueNAS SCALE UI: "Save 14 for 10.0.0.214?" — a
  // numeric setting classified as the username. An offer with obvious rubbish
  // in it teaches people to dismiss the toast unread, so none is made.
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);
  await bg.send({ type: MSG.SETUP, password: 'correct horse' });

  const refused = await bg.send(
    { type: MSG.CAPTURE, username: '14', password: 'a real password' },
    PAGE('https://10.0.0.214/ui/apps'),
  );
  assert.equal(refused.ok, false);
  assert.equal(bg.bencpass.takePending(5), undefined, 'an offer was made anyway');

  // The same submission with a username a person could actually have is the
  // control: everything else about the capture was fine.
  const offered = await bg.send(
    { type: MSG.CAPTURE, username: 'admin', password: 'a real password' },
    PAGE('https://10.0.0.214/ui/apps'),
  );
  assert.equal(offered.ok, true);
  const pending = bg.bencpass.takePending(5);
  assert.equal(pending.username, 'admin');
});

test('a password box full of mask characters is not offered, and cannot overwrite', async () => {
  // A password field pre-filled with asterisks standing in for a value already
  // set. Stored, it looks exactly like a Reveal button that does not work —
  // and one of these, saved by another manager a decade ago, rode an import
  // into a real vault. Capture is where this one can still be refused.
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);
  await bg.send({ type: MSG.SETUP, password: 'correct horse' });

  const id = await bg.bencpass.vault.add({
    title: '10.0.0.214',
    username: 'admin',
    password: 'the real one',
    urls: ['https://10.0.0.214'],
  });

  const refused = await bg.send(
    { type: MSG.CAPTURE, username: 'admin', password: '********' },
    PAGE('https://10.0.0.214/ui/apps'),
  );
  assert.equal(refused.ok, false);
  assert.equal(bg.bencpass.takePending(5), undefined, 'an offer was made anyway');
  assert.equal(
    bg.bencpass.vault.get(id).password,
    'the real one',
    'a mask string was written over a real password',
  );

  // The control: the same form, a password someone actually typed.
  const offered = await bg.send(
    { type: MSG.CAPTURE, username: 'admin', password: 'a real password' },
    PAGE('https://10.0.0.214/ui/apps'),
  );
  assert.equal(offered.ok, true);
  assert.equal(bg.bencpass.takePending(5).password, 'a real password');
});

test('a generated password still completes its record when the username is rubbish', async () => {
  // The interaction that must not break: generating IS saving (the provisional
  // entry exists before the page ever sees the password), and the submit is
  // what completes it. A numeric non-username must not leave that half-made —
  // and must not be written into it either.
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);
  await bg.send({ type: MSG.SETUP, password: 'correct horse' });

  const id = await bg.bencpass.vault.add({
    title: '10.0.0.214',
    username: '',
    password: 'gen-Xy7!pass',
    urls: ['https://10.0.0.214'],
    provisional: true,
  });

  const reply = await bg.send(
    { type: MSG.CAPTURE, username: '14', password: 'gen-Xy7!pass' },
    PAGE('https://10.0.0.214/ui/apps'),
  );
  assert.equal(reply.ok, true);

  const rec = bg.bencpass.vault.get(id);
  assert.equal(rec.provisional, false, 'the record was left half-made');
  assert.equal(rec.username, '', 'a port number was stored as the username');
});

// ---- "never for this site" ---------------------------------------------------

/** An extension page whose sender carries the capture's tab. */
const EXT_PAGE = (tabId) => ({ url: 'moz-extension://test/ui/manager.html', tab: { id: tabId } });

test('NEVER silences the whole site, survives in settings, and can be undone there', async () => {
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);
  await bg.send({ type: MSG.SETUP, password: 'correct horse' });

  // A real offer stands...
  const offered = await bg.send(
    { type: MSG.CAPTURE, username: 'ben', password: 'pw-one' },
    PAGE('https://login.example.com/signin'),
  );
  assert.equal(offered.ok, true);

  // ...and "never" clears it and records the registrable domain, not the
  // subdomain the person happened to be on.
  const never = await bg.send({ type: MSG.NEVER }, EXT_PAGE(5));
  assert.equal(never.ok, true);
  assert.equal(never.site, 'example.com');
  assert.equal(bg.bencpass.takePending(5), undefined, 'the pending offer outlived the answer');

  // The next sign-in on any host of that site is not offered — www as much as
  // login, or the button would read as broken.
  const again = await bg.send(
    { type: MSG.CAPTURE, username: 'ben', password: 'pw-two' },
    PAGE('https://www.example.com/signin'),
  );
  assert.equal(again.ok, false);
  assert.equal(bg.bencpass.takePending(5), undefined);

  // Addresses typed there are covered too: the person silenced the asking.
  const addr = await bg.send(
    {
      type: MSG.CAPTURE,
      kind: 'address',
      address: { 'address-line1': '1 Test Street', 'postal-code': 'SW1A 1AA', 'address-level2': 'London' },
    },
    PAGE('https://www.example.com/checkout'),
  );
  assert.equal(addr.ok, false);

  // Other sites are untouched.
  const other = await bg.send(
    { type: MSG.CAPTURE, username: 'ben', password: 'pw-three' },
    PAGE('https://other.net/signin'),
  );
  assert.equal(other.ok, true);
  bg.bencpass.takePending(5);

  // The decision is visible where it can be undone, survives a restart, and
  // removing it there brings the offers back.
  const s = await bg.send({ type: MSG.SETTINGS_GET });
  assert.deepEqual(s.neverSites, ['example.com']);
  assert.deepEqual(fake.data.get('bencpass.settings')?.neverSites, ['example.com']);

  await bg.send({ type: MSG.SETTINGS_SET, neverSites: [] });
  const back = await bg.send(
    { type: MSG.CAPTURE, username: 'ben', password: 'pw-two' },
    PAGE('https://www.example.com/signin'),
  );
  assert.equal(back.ok, true);
});

test('a generated password is still kept and completed on a silenced site', async () => {
  // The interaction TODO warned about: generating IS saving (the provisional
  // entry exists before the page sees the password), and a "never" preference
  // set weeks earlier must not turn that into a password that vanishes. The
  // block applies to captures of passwords typed by hand, and only those.
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);
  await bg.send({ type: MSG.SETUP, password: 'correct horse' });
  await bg.send({ type: MSG.SETTINGS_SET, neverSites: ['10.0.0.214'] });

  // What handleGenerate leaves behind the moment a password is generated.
  const id = await bg.bencpass.vault.add({
    title: '10.0.0.214',
    username: '',
    password: 'gen-Zq9!pass',
    urls: ['https://10.0.0.214'],
    provisional: true,
  });

  // The submit arrives: the record is completed, silence or no silence.
  const done = await bg.send(
    { type: MSG.CAPTURE, username: 'admin', password: 'gen-Zq9!pass' },
    PAGE('https://10.0.0.214/ui/signup'),
  );
  assert.equal(done.ok, true);
  const rec = bg.bencpass.vault.get(id);
  assert.equal(rec.provisional, false, 'the generated password was left half-made');
  assert.equal(rec.username, 'admin');

  // A password typed by hand on the same site is what the silence is for.
  const typed = await bg.send(
    { type: MSG.CAPTURE, username: 'admin', password: 'typed-by-hand' },
    PAGE('https://10.0.0.214/ui/signin'),
  );
  assert.equal(typed.ok, false);
  assert.equal(bg.bencpass.takePending(5), undefined);
});

test('the never list is normalised on the way in and refused from page senders', async () => {
  const fake = fakeBrowser();
  const bg = await loadBackground(fake);
  await bg.send({ type: MSG.SETUP, password: 'correct horse' });

  // Whatever shape a person pastes, what is stored is what is matched.
  const set = await bg.send({
    type: MSG.SETTINGS_SET,
    neverSites: ['https://www.Example.com/login', 'login.example.com', '10.0.0.214', 'not a host at all', 42, ''],
  });
  assert.equal(set.ok, true);
  assert.deepEqual(set.settings.neverSites, ['example.com', '10.0.0.214']);

  // NEVER writes a durable preference, so a content script cannot send it —
  // the same line SAVE draws.
  await bg.send(
    { type: MSG.CAPTURE, username: 'ben', password: 'pw' },
    PAGE('https://other.net/signin'),
  );
  const refused = await bg.send({ type: MSG.NEVER }, PAGE('https://other.net/signin'));
  assert.equal(refused?.ok ?? false, false, 'a page sender silenced a site');
  assert.ok(bg.bencpass.takePending(5), 'the page discarded an offer it should not reach');
  const s = await bg.send({ type: MSG.SETTINGS_GET });
  assert.deepEqual(s.neverSites, ['example.com', '10.0.0.214'], 'the page grew the list');
});
