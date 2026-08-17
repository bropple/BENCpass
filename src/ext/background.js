// The background page. The only component that holds the vault key.
//
// Everything that decides whether a secret may leave happens here, and it is
// decided from `sender` — the browser's own account of which tab and frame a
// message came from — never from anything the message claims about itself. A
// compromised content script can lie about its origin; it cannot lie to the
// browser about which frame it is.

import { Vault } from '../core/vault.js';
import { WebExtStorage } from '../core/storage.js';
import { matchesFor, canFill, canFillAddress, addressesFor, hostOf } from '../core/match.js';
import { classifyGroups } from '../core/fields.js';
import { generate } from '../core/generate.js';
import { SyncClient, syncOnce, loadSyncState, dumpSyncState } from '../core/sync.js';
import { MSG, publicCandidate, publicAddress, isMessage, asString, asId } from './protocol.js';

const AUTOLOCK_MS = 15 * 60 * 1000;
const SYNC_INTERVAL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 60 * 1000;

const store = new WebExtStorage();
const settingsStore = { key: 'bencpass.settings' };

let vault = null;
let settings = { endpoint: '', deviceId: '', deviceKey: '', autolockMs: AUTOLOCK_MS, allowInsecure: false };
let syncState = loadSyncState(null);
let autolockTimer = null;

/** Menus currently on screen, keyed by an unguessable id. */
const sessions = new Map();

/** Credentials seen submitted but not yet saved, keyed by tab. */
const pendingCaptures = new Map();

// ---- lifecycle -------------------------------------------------------------

async function boot() {
  const persisted = await store.read();
  if (persisted) vault = Vault.load(persisted);

  const s = await store.read(settingsStore.key);
  if (s) {
    settings = { ...settings, ...s };
    syncState = loadSyncState(s.syncState);
  }
  paintBadge();
}

const persistVault = () => store.write(vault.toJSON());

async function persistSettings() {
  await store.write({ ...settings, syncState: dumpSyncState(syncState) }, settingsStore.key);
}

function bumpAutolock() {
  clearTimeout(autolockTimer);
  if (!vault || vault.locked) return;
  autolockTimer = setTimeout(() => lock(), settings.autolockMs ?? AUTOLOCK_MS);
}

function lock() {
  vault?.lock();
  sessions.clear();
  clearTimeout(autolockTimer);
  paintBadge();
  broadcastLockState();
}

// Locking when the screen locks or the machine sleeps is the case an idle timer
// misses, and it is the one that matters on a laptop lid.
//
// Guarded, and not merely for tidiness: this used to run unguarded at module
// top level, and `browser.idle` is undefined without the `idle` permission —
// which was missing. The TypeError killed the whole background page before the
// message listener below was ever registered, so the popup came up blank, no
// field ever got an anchor, and the manager quietly fell back to a second
// vault. One missing permission, and every symptom pointed somewhere else.
//
// Nothing optional runs unguarded at load time here any more.
try {
  browser.idle.setDetectionInterval(60);
  browser.idle.onStateChanged.addListener((state) => {
    if (state === 'locked') lock();
  });
} catch (err) {
  console.warn('BENCpass: idle detection unavailable, falling back to the timer alone', err);
}

function paintBadge() {
  const pending = pendingCaptures.size > 0;
  browser.browserAction.setBadgeText({ text: pending ? '!' : '' });
  browser.browserAction.setBadgeBackgroundColor({ color: pending ? '#e8b23d' : '#3d7dbf' });
  paintIcon();
}

/**
 * The toolbar icon carries the lock state, same as the gate and the in-page
 * anchor: red visor shut, green visor open. One glance, no clicking.
 */
function paintIcon() {
  const shut = !vault || vault.locked;
  const suffix = shut ? '-locked' : '';
  browser.browserAction
    .setIcon({
      path: {
        16: `icons/16${suffix}.png`,
        32: `icons/32${suffix}.png`,
        48: `icons/48${suffix}.png`,
      },
    })
    .catch(() => {});
}

/** Anchors already drawn in open tabs cannot see the vault; tell them. */
async function broadcastLockState() {
  const shut = !vault || vault.locked;
  const tabs = await browser.tabs.query({}).catch(() => []);
  for (const tab of tabs) {
    browser.tabs
      .sendMessage(tab.id, { type: MSG.LOCKSTATE, locked: shut })
      .catch(() => {
        /* no content script in that tab, which is normal */
      });
  }
}

// ---- origin, derived rather than believed ----------------------------------

/**
 * Where a message actually came from.
 *
 * `sender.url` is the frame's own URL as the browser sees it, and `sender.tab.url`
 * is the top-level page. Comparing the two is how a login form inside a
 * third-party iframe is told apart from one belonging to the site you are
 * looking at.
 */
function originOf(sender) {
  const frameUrl = sender?.url ?? '';
  const pageUrl = sender?.tab?.url ?? frameUrl;
  let protocol = 'https:';
  try {
    protocol = new URL(frameUrl).protocol;
  } catch {
    /* left as https:, which is the stricter assumption */
  }
  return {
    frameHost: hostOf(frameUrl),
    pageHost: hostOf(pageUrl),
    frameProtocol: protocol,
    tabId: sender?.tab?.id ?? null,
    frameId: sender?.frameId ?? 0,
  };
}

const isExtensionPage = (sender) =>
  typeof sender?.url === 'string' && sender.url.startsWith(browser.runtime.getURL(''));

const newSessionId = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');

function reapSessions() {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.created > SESSION_TTL_MS) sessions.delete(id);
  }
}

// ---- handlers --------------------------------------------------------------

/**
 * The only message types a content script may send.
 *
 * Everything else is for extension pages — the popup, the overlay, the manager.
 * This is an allow-list at the single entry point rather than a guard inside
 * each handler, because the per-handler version is exactly what went wrong: six
 * of them were written without one, including SEARCH, which answers an empty
 * query with the entire decrypted vault index.
 *
 * A page cannot reach this listener directly in any case — content scripts run
 * in an isolated world and page script has no `browser.runtime` — so this is
 * defence in depth against a compromised content script rather than against the
 * page itself. For a password manager that is worth having anyway.
 */
const CONTENT_CALLABLE = new Set([MSG.DESCRIBE, MSG.CANDIDATES, MSG.CAPTURE]);

browser.runtime.onMessage.addListener((msg, sender) => {
  if (!isMessage(msg)) return; // unknown shapes are dropped without reply
  if (!CONTENT_CALLABLE.has(msg.type) && !isExtensionPage(sender)) return;
  reapSessions();

  switch (msg.type) {
    case MSG.CANDIDATES:
      return handleCandidates(msg, sender);
    case MSG.DESCRIBE:
      return handleDescribe(msg, sender);
    case MSG.SESSION:
      return handleSession(msg, sender);
    case MSG.CHOOSE:
      return handleChoose(msg, sender);
    case MSG.GENERATE:
      return handleGenerate(msg, sender);
    case MSG.CAPTURE:
      return handleCapture(msg, sender);
    case MSG.STATE:
      return handleState(sender);
    case MSG.UNLOCK:
      return handleUnlock(msg, sender);
    case MSG.LOCK:
      lock();
      return Promise.resolve({ ok: true });
    case MSG.SEARCH:
      return handleSearch(msg, sender);
    case MSG.SYNC:
      return handleSync();
    case MSG.SAVE:
      return handleSave(sender);
    case MSG.DISCARD:
      return handleDiscard();
    case MSG.CLOSE:
      return handleClose(msg, sender);
    default:
      return;
  }
});

/**
 * What the content script is allowed to know about its frame.
 *
 * Titles and usernames only — enough to draw a menu. No password crosses here.
 */
async function handleCandidates(msg, sender) {
  const origin = originOf(sender);

  // A locked vault still gets a session. Returning nothing made the menu look
  // broken rather than locked, and left no route to unlocking from the field
  // the user was actually standing in.
  if (!vault || vault.locked) {
    const sessionId = newSessionId();
    sessions.set(sessionId, {
      created: Date.now(),
      tabId: origin.tabId,
      frameId: origin.frameId,
      kind: 'locked',
      ids: [],
    });
    return { locked: true, sessionId, candidates: [{ id: 'locked' }] };
  }

  bumpAutolock();
  if (!origin.frameHost) return { locked: false, candidates: [] };

  const wantAddresses = msg.kind === 'address';

  // An address has no host to match, but the frame and transport checks are the
  // same ones a credential gets. ARCHITECTURE.md §3 says so; the first cut of
  // this branch exempted them, which would have handed a home address to any
  // third-party frame that asked.
  if (
    wantAddresses &&
    !canFillAddress(origin.frameHost, {
      pageHost: origin.pageHost,
      frameProtocol: origin.frameProtocol,
      allowInsecure: settings.allowInsecure,
    }).ok
  ) {
    return { locked: false, candidates: [] };
  }

  const records = wantAddresses
    ? addressesFor(vault.list())
    : matchesFor(vault.list(), origin.frameHost).filter(
        (r) =>
          canFill(r, origin.frameHost, {
            pageHost: origin.pageHost,
            frameProtocol: origin.frameProtocol,
            allowInsecure: settings.allowInsecure,
          }).ok,
      );

  if (!records.length) return { locked: false, candidates: [] };

  const sessionId = newSessionId();
  sessions.set(sessionId, {
    created: Date.now(),
    tabId: origin.tabId,
    frameId: origin.frameId,
    frameHost: origin.frameHost,
    pageHost: origin.pageHost,
    frameProtocol: origin.frameProtocol,
    kind: wantAddresses ? 'address' : 'login',
    ids: records.map((r) => r.id),
  });

  return {
    locked: false,
    sessionId,
    candidates: records.map(wantAddresses ? publicAddress : publicCandidate),
  };
}

/**
 * Classify a frame's fields, one form at a time. Pure judgement, kept out of
 * the content script.
 */
async function handleDescribe(msg, sender) {
  const fields = Array.isArray(msg.fields) ? msg.fields.slice(0, 300) : [];
  return {
    locked: !vault || vault.locked,
    groups: classifyGroups(fields).map((g) => ({
      group: g.group,
      login: describeIndices(g.login),
      address: g.address.map((a) => ({ index: a.field.index, token: a.token })),
      usernameOnly: g.usernameOnly,
    })),
  };
}

const describeIndices = (c) => ({
  username: c.username?.index ?? null,
  password: c.password?.index ?? null,
  newPassword: c.newPassword?.index ?? null,
  otp: c.otp?.index ?? null,
});

/** The overlay asking what to draw. Only an extension page may ask. */
async function handleSession(msg, sender) {
  if (!isExtensionPage(sender)) return { candidates: [] };
  const session = sessions.get(asString(msg.sessionId, 64));
  if (!session) return { candidates: [] };
  if (session.kind === 'locked' || !vault || vault.locked) {
    return { kind: 'locked', candidates: [] };
  }

  const byId = new Map(vault.list().map((r) => [r.id, r]));
  const records = session.ids.map((id) => byId.get(id)).filter(Boolean);
  return {
    kind: session.kind,
    candidates: records.map(session.kind === 'address' ? publicAddress : publicCandidate),
  };
}

/**
 * The user picked an entry. This is the only path by which a secret leaves.
 *
 * Re-checked from scratch rather than trusting the session: the vault may have
 * been locked, the record deleted or its URLs edited since the menu was drawn.
 */
async function handleChoose(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false, reason: 'not-extension' };
  if (!vault || vault.locked) return { ok: false, reason: 'locked' };

  // The popup names an entry but never an origin. The tab it would fill is
  // resolved here, from the browser's own record of which tab is in front —
  // so a popup cannot ask for a credential to be typed into a page of its
  // choosing, and the origin check is against the same host the user is looking
  // at rather than one supplied in a message.
  if (msg.active) return chooseForActiveTab(asId(msg.recordId));

  const session = sessions.get(asString(msg.sessionId, 64));
  const recordId = asId(msg.recordId);
  if (!session || !recordId || !session.ids.includes(recordId)) {
    return { ok: false, reason: 'stale-session' };
  }

  const record = vault.get(recordId);
  if (!record) return { ok: false, reason: 'gone' };

  let values;
  if (session.kind === 'address') {
    const verdict = canFillAddress(session.frameHost, {
      pageHost: session.pageHost,
      frameProtocol: session.frameProtocol,
      allowInsecure: settings.allowInsecure,
    });
    if (!verdict.ok) return { ok: false, reason: verdict.reason };
    values = addressValues(record);
  } else {
    const verdict = canFill(record, session.frameHost, {
      pageHost: session.pageHost,
      frameProtocol: session.frameProtocol,
      allowInsecure: settings.allowInsecure,
    });
    if (!verdict.ok) return { ok: false, reason: verdict.reason };
    values = { username: record.username ?? '', password: record.password ?? '' };
    await vault.touchUsed(recordId).then(persistVault).catch(() => {});
  }

  await browser.tabs.sendMessage(
    session.tabId,
    { type: MSG.FILL, kind: session.kind, values },
    { frameId: session.frameId },
  );

  sessions.delete(asString(msg.sessionId, 64));
  bumpAutolock();
  return { ok: true };
}

async function chooseForActiveTab(recordId) {
  if (!recordId) return { ok: false, reason: 'gone' };
  const tab = (await browser.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab?.id) return { ok: false, reason: 'no-tab' };

  const record = vault.get(recordId);
  if (!record) return { ok: false, reason: 'gone' };

  const host = hostOf(tab.url ?? '');
  let frameProtocol = 'https:';
  try {
    frameProtocol = new URL(tab.url).protocol;
  } catch {
    /* stricter assumption retained */
  }

  const verdict = canFill(record, host, {
    pageHost: host,
    frameProtocol,
    allowInsecure: settings.allowInsecure,
  });
  if (!verdict.ok) return { ok: false, reason: verdict.reason };

  await browser.tabs.sendMessage(
    tab.id,
    {
      type: MSG.FILL,
      kind: 'login',
      values: { username: record.username ?? '', password: record.password ?? '' },
    },
    { frameId: 0 },
  );

  await vault.touchUsed(recordId).then(persistVault).catch(() => {});
  bumpAutolock();
  return { ok: true };
}

async function handleClose(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  const session = sessions.get(asString(msg.sessionId, 64));
  if (!session) return { ok: false };
  sessions.delete(asString(msg.sessionId, 64));
  await browser.tabs
    .sendMessage(session.tabId, { type: MSG.DISMISS }, { frameId: session.frameId })
    .catch(() => {});
  return { ok: true };
}

/**
 * Keep the credentials the user submitted.
 *
 * Only ever reached by the user pressing Save in the popup. A capture sits in
 * memory until then and is discarded when the tab closes.
 */
async function handleSave(sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  if (!vault || vault.locked) return { ok: false, reason: 'locked' };

  const tab = (await browser.tabs.query({ active: true, currentWindow: true }))[0];
  const pending = tab ? pendingCaptures.get(tab.id) : null;
  if (!pending) return { ok: false, reason: 'nothing-pending' };

  if (pending.existingId) {
    // The old password is kept in the record's history by applyPatch, so a
    // capture that turns out to be a typo is recoverable.
    await vault.update(pending.existingId, { password: pending.password });
  } else {
    await vault.add({
      title: pending.host,
      username: pending.username,
      password: pending.password,
      urls: [pending.url],
    });
  }

  await persistVault();
  pendingCaptures.delete(tab.id);
  clearCaptureNotice();
  paintBadge();
  bumpAutolock();
  return { ok: true };
}

async function handleDiscard() {
  const tab = (await browser.tabs.query({ active: true, currentWindow: true }))[0];
  if (tab) pendingCaptures.delete(tab.id);
  clearCaptureNotice();
  paintBadge();
  return { ok: true };
}

const addressValues = (r) =>
  Object.fromEntries(
    [
      'name',
      'organization',
      'address-line1',
      'address-line2',
      'address-level1',
      'address-level2',
      'postal-code',
      'country',
      'tel',
      'email',
    ]
      .map((k) => [k, r[k] ?? ''])
      .filter(([, v]) => v !== ''),
  );

/** A generated password goes to the page, but is never stored until saved. */
async function handleGenerate(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  const session = sessions.get(asString(msg.sessionId, 64));
  if (!session) return { ok: false };

  const password = generate({ length: 20 });
  await browser.tabs.sendMessage(
    session.tabId,
    { type: MSG.FILL, kind: 'generated', values: { password } },
    { frameId: session.frameId },
  );
  return { ok: true, password };
}

/**
 * Credentials the user submitted, offered for saving.
 *
 * The password here came from the page — the user typed it — so receiving it
 * costs nothing that was not already on screen. It is held in memory only until
 * the user accepts or dismisses it, and never written without that.
 */
async function handleCapture(msg, sender) {
  if (!vault || vault.locked) return { ok: false };
  const origin = originOf(sender);
  if (!origin.frameHost || origin.tabId === null) return { ok: false };

  const username = asString(msg.username, 256);
  const password = asString(msg.password, 1024);
  if (!password) return { ok: false };

  const existing = matchesFor(vault.list(), origin.frameHost).find(
    (r) => (r.username ?? '') === username,
  );
  if (existing && existing.password === password) return { ok: false }; // nothing new

  pendingCaptures.set(origin.tabId, {
    host: origin.frameHost,
    url: `${origin.frameProtocol}//${origin.frameHost}`,
    username,
    password,
    existingId: existing?.id ?? null,
  });
  paintBadge();
  announceCapture(origin.frameHost, username, Boolean(existing));
  return { ok: true };
}

const CAPTURE_NOTICE = 'bencpass-capture';

/**
 * Say out loud that there is something to save.
 *
 * A badge on the toolbar icon is the conventional signal and it is far too
 * quiet — in Zen the chrome can be hidden entirely, and the offer then exists
 * only somewhere the person is not looking. No password goes in the text.
 */
function announceCapture(host, username, isUpdate) {
  const who = username || 'this login';
  browser.notifications
    .create(CAPTURE_NOTICE, {
      type: 'basic',
      iconUrl: browser.runtime.getURL('ext/icons/64.png'),
      title: isUpdate ? 'BENCpass — update password?' : 'BENCpass — save login?',
      message: isUpdate
        ? `The password for ${who} on ${host} has changed. Open BENCpass to update it.`
        : `Save ${who} for ${host}? Open BENCpass to keep it.`,
    })
    .catch((err) => {
      // Not swallowed. Windows in particular can refuse these outright — the
      // OS notification setting for the browser, or Focus Assist — and the
      // failure is then completely silent, which is indistinguishable from the
      // code never having run. The badge still stands either way.
      console.warn('BENCpass: could not show the save notification', err);
    });
}

const clearCaptureNotice = () =>
  browser.notifications.clear(CAPTURE_NOTICE).catch(() => {});

browser.notifications.onClicked.addListener(async () => {
  try {
    await browser.browserAction.openPopup();
  } catch {
    await browser.runtime.openOptionsPage();
  }
});

// ---- popup surface ---------------------------------------------------------

async function handleState(sender) {
  if (!isExtensionPage(sender)) return { locked: true, candidates: [] };
  const tab = (await browser.tabs.query({ active: true, currentWindow: true }))[0];
  const host = hostOf(tab?.url ?? '');
  const pending = tab ? pendingCaptures.get(tab.id) : null;

  return {
    hasVault: Boolean(vault),
    locked: !vault || vault.locked,
    host,
    endpoint: settings.endpoint,
    pending: pending
      ? { host: pending.host, username: pending.username, update: Boolean(pending.existingId) }
      : null,
    candidates:
      vault && !vault.locked && host
        ? matchesFor(vault.list(), host).map(publicCandidate)
        : [],
  };
}

async function handleUnlock(msg, sender) {
  // Without this the reply is a master-password verification oracle: it says
  // 'bad-password' rather than 'error', which is precisely the distinction the
  // manager UI refuses to draw for the person in front of it.
  if (!isExtensionPage(sender)) return { ok: false, reason: 'error' };
  if (!vault) return { ok: false, reason: 'no-vault' };
  try {
    await vault.unlock(asString(msg.password, 1024));
    bumpAutolock();
    paintBadge();
    broadcastLockState();
    scheduleSync();
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: err.code === 'unwrap-failed' ? 'bad-password' : 'error' };
  }
}

async function handleSearch(msg, sender) {
  if (!isExtensionPage(sender)) return { results: [] };
  if (!vault || vault.locked) return { results: [] };
  // After the authorisation check, not before — a caller that is refused must
  // not be able to hold the vault unlocked by asking.
  bumpAutolock();
  return { results: vault.search(asString(msg.query, 256)).map(publicCandidate) };
}

// ---- sync ------------------------------------------------------------------

function client() {
  if (!settings.endpoint || !settings.deviceId || !settings.deviceKey) return null;
  return new SyncClient({
    endpoint: settings.endpoint,
    deviceId: settings.deviceId,
    key: Uint8Array.from(atob(settings.deviceKey), (c) => c.charCodeAt(0)),
  });
}

async function handleSync() {
  const c = client();
  if (!c || !vault) return { ok: false, reason: 'not-configured' };
  try {
    const result = await syncOnce(vault, c, syncState);
    await persistVault();
    await persistSettings();
    return { ok: true, ...result, conflicts: result.conflicts.length };
  } catch (err) {
    return { ok: false, reason: err.code ?? 'error', message: err.message };
  }
}

// Sync runs on a locked vault — the merge needs nothing inside the ciphertext —
// so this does not wait for an unlock.
function scheduleSync() {
  setInterval(() => {
    if (client()) handleSync().catch(() => {});
  }, SYNC_INTERVAL_MS);
}

// ---- wiring ----------------------------------------------------------------

browser.tabs.onRemoved.addListener((tabId) => {
  pendingCaptures.delete(tabId);
  paintBadge();
});

browser.commands.onCommand.addListener(async (command) => {
  if (command !== 'fill') return;
  const tab = (await browser.tabs.query({ active: true, currentWindow: true }))[0];
  if (tab) browser.tabs.sendMessage(tab.id, { type: MSG.DISMISS, open: true }).catch(() => {});
});

// Exposed for the manager page, which runs in the same extension and needs the
// live vault rather than a second copy of it.
window.bencpass = {
  get vault() {
    return vault;
  },
  setVault(v) {
    vault = v;
    bumpAutolock();
  },
  get settings() {
    return settings;
  },
  async saveSettings(next) {
    settings = { ...settings, ...next };
    await persistSettings();
  },
  takePending(tabId) {
    const p = pendingCaptures.get(tabId);
    pendingCaptures.delete(tabId);
    paintBadge();
    return p;
  },
  persistVault,
  sync: handleSync,
  lock,
};

boot();
