// The background page. The only component that holds the vault key.
//
// Everything that decides whether a secret may leave happens here, and it is
// decided from `sender` — the browser's own account of which tab and frame a
// message came from — never from anything the message claims about itself. A
// compromised content script can lie about its origin; it cannot lie to the
// browser about which frame it is.

import { Vault } from '../core/vault.js';
import { WebExtStorage } from '../core/storage.js';
import {
  matchesFor,
  canFill,
  canFillAddress,
  addressesFor,
  hostOf,
  isPrivateHost,
  captureTarget,
  registrableDomain,
  normaliseHost,
} from '../core/match.js';
import { classifyGroups, plausibleUsername, plausiblePassword } from '../core/fields.js';
import {
  ADDRESS_TOKENS,
  valuesForTokens,
  normalizeCaptured,
  isAddressish,
  matchesStored,
  addressSummary,
} from '../core/address.js';
import { generate } from '../core/generate.js';
import { keepGenerated, completeGenerated } from '../core/provisional.js';
import {
  SyncClient,
  syncOnce,
  joinVault,
  loadSyncState,
  dumpSyncState,
  packEnrolCode,
  PROTOCOL,
} from '../core/sync.js';
import { MSG, publicCandidate, publicAddress, isMessage, asString, asId } from './protocol.js';

const AUTOLOCK_MS = 15 * 60 * 1000;
const SYNC_INTERVAL_MS = 5 * 60 * 1000;
const SESSION_TTL_MS = 60 * 1000;

const store = new WebExtStorage();
const settingsStore = { key: 'bencpass.settings' };

let vault = null;
let settings = {
  endpoint: '', // the address tried first, usually the LAN one
  fallbackEndpoint: '', // the same server by another route, usually Tailscale
  deviceId: '',
  deviceKey: '',
  autolockMs: AUTOLOCK_MS,
  allowInsecure: false,
  webauthnCredentialId: '', // which credential derives this vault's device secret
  syncPreferred: '', // the server address that answered last
  syncPreferredAt: 0, // and when, so the preference can go stale
  // The sequence floor off the enrolment code this machine last redeemed. It
  // arrived by hand — minted by an already-enrolled machine, carried by a
  // person — which is the one channel the server cannot rewrite, and it is
  // what a joining machine starts its rollback defence from. 0 means the code
  // carried none (the server's own bootstrap code, or an older build's).
  enrolFloor: 0,
  // Sites whose submits are never offered for saving — registrable domains
  // (or bare hosts/IPs where no domain exists), added from the toast's "Never
  // for this site" and edited in Settings → Filling. Kept beside the settings
  // rather than in the vault on purpose: it is a preference about a site, not
  // a secret, and a vault entry would sync a personal "stop asking" to every
  // machine whether or not it was wanted there. The cost is re-declaring it
  // per machine, which is the cheaper mistake to correct.
  neverSites: [],
};
let syncState = loadSyncState(null);
let autolockTimer = null;
let autolockAt = 0; // when the vault will shut, for anything that wants to show it
let lastSyncAt = 0; // when a sync last succeeded, for the settings panel
let lastSyncVia = ''; // which of the server's addresses answered

// The last sync refusal worth a person's attention, kept until a sync
// succeeds. The periodic background sync swallows its errors by design — there
// is nobody to show them to at 3am — but a refusal that names tampering, a
// rollback or a dropped write must not evaporate with the tick that found it:
// it is held here and shown wherever sync status is shown.
let lastSyncProblem = null; // { reason, message, at } | null
const LOUD_REASONS = new Set(['tampered', 'rollback', 'dropped-push', 'key-mismatch']);

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
  scheduleSync();

  // Firefox opens the sidebar by itself when an extension carrying a
  // sidebar_action is installed — `open_at_install` defaults to true, and
  // `web-ext run` reinstalls on every launch, so it appeared every single time.
  // The manifest now says false, which is the actual fix; this stays for the
  // other case, a session restored with our sidebar last open. Closing needs no
  // user gesture, unlike opening.
  browser.sidebarAction?.close?.().catch?.(() => {});
}

const persistVault = () => store.write(vault.toJSON());

async function persistSettings() {
  await store.write({ ...settings, syncState: dumpSyncState(syncState) }, settingsStore.key);
}

function bumpAutolock() {
  clearTimeout(autolockTimer);
  autolockAt = 0;
  if (!vault || vault.locked) return;

  // `||` rather than `??`: a stored 0 must not be taken literally and lock the
  // vault on the next tick.
  const after = settings.autolockMs || AUTOLOCK_MS;
  autolockAt = Date.now() + after;
  autolockTimer = setTimeout(() => lock(), after);
}

/**
 * Fork any conflict copies a locked-vault sync parked, now that there is a key.
 *
 * Called after every successful unlock, whichever surface it came through. The
 * unlocked sync path does this itself inside syncOnce; this covers the person
 * who unlocks, looks, and locks again before the five-minute timer ever runs —
 * they deserve to see the "(conflict)" entries too, not a list that pretends
 * the machines agreed.
 */
async function forkParkedConflicts() {
  if (!vault || vault.locked || !vault.parked.length) return;
  try {
    const forked = await vault.resolveParked();
    if (forked.length) await persistVault();
  } catch (err) {
    console.error('BENCpass: could not fork parked conflict copies', err);
  }
}

function lock() {
  vault?.lock();
  sessions.clear();
  // A pending capture holds a password in the clear, waiting for someone to
  // agree to keep it. Locking is that person saying they have finished, so it
  // goes with everything else — the alternative is a plaintext password living
  // on past the lock in a Map. The toast goes too, since a locked vault cannot
  // save anything and an offer that cannot be accepted is just a lie.
  pendingCaptures.clear();
  clearTimeout(autolockTimer);
  autolockAt = 0;
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
  // Extension pages first. tabs.sendMessage below only reaches content
  // scripts, so a manager tab or the sidebar — which is not a tab at all —
  // never heard about an idle auto-lock: the app pane stayed up, and a
  // revealed password stayed on screen in front of a vault that was shut.
  browser.runtime.sendMessage({ type: MSG.LOCKSTATE, locked: shut }).catch(() => {
    /* no extension page open, which is normal */
  });
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
  // Nothing is answered before boot() has read storage. Answering early is
  // answering from a `vault` that is still null while the read is in flight:
  // the manager took that null for "no vault on this machine" and painted the
  // setup gate over a vault holding 534 records — one typed password away from
  // persisting an empty vault on top of them. handleSetup refuses that
  // overwrite on its own (see there), but the wrong offer must not appear
  // either, so every reply waits for the answer to exist.
  return ready.then(() => dispatch(msg, sender));
});

function dispatch(msg, sender) {
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
    case MSG.NOTICE_STATE:
      return handleNoticeState(msg, sender);
    case MSG.SETTINGS_GET:
      return handleSettingsGet();
    case MSG.SETTINGS_SET:
      return handleSettingsSet(msg);
    case MSG.SETUP:
      return handleSetup(msg, sender);
    case MSG.JOIN:
      return handleJoin(msg, sender);
    case MSG.DEVICES:
      return handleDevices(sender);
    case MSG.MINT_CODE:
      return handleMintCode(sender);
    case MSG.DEVICE_FORGET:
      return handleDeviceForget(msg, sender);
    case MSG.DEVICE_RENAME:
      return handleDeviceRename(msg, sender);
    case MSG.SYNC_FORGET:
      return handleSyncForget(sender);
    case MSG.BIO_STATE:
      return handleBioState();
    case MSG.BIO_ENROL:
      return handleBioEnrol(msg);
    case MSG.BIO_UNLOCK:
      return handleBioUnlock(msg, sender);
    case MSG.BIO_FORGET:
      return handleBioForget();
    case MSG.SAVE:
      return handleSave(msg, sender);
    case MSG.DISCARD:
      return handleDiscard(msg, sender);
    case MSG.NEVER:
      return handleNever(msg, sender);
    case MSG.CLOSE:
      return handleClose(msg, sender);
    case MSG.OPEN_MANAGER:
      return handleOpenManager(msg, sender);
    case MSG.UNLOCKED:
      return handleUnlocked(sender);
    default:
      return;
  }
}

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

  // A new-password box is offered a generated password and nothing else. The
  // stored pool is deliberately absent: this is the one moment where reuse
  // costs nothing to avoid, and filling an old password into a "choose a
  // password" field is how one leaked credential becomes several.
  if (msg.kind === 'signup') {
    const sessionId = newSessionId();
    sessions.set(sessionId, {
      created: Date.now(),
      tabId: origin.tabId,
      frameId: origin.frameId,
      frameHost: origin.frameHost,
      pageHost: origin.pageHost,
      frameProtocol: origin.frameProtocol,
      kind: 'signup',
      ids: [],
    });
    return { locked: false, sessionId, candidates: [{ id: 'generate' }] };
  }

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
    // Which parts of an address this form has fields for. Filtered against the
    // known tokens because it came from the content script, which is the least
    // trusted part of the extension — though the worst a page could do by
    // lying is ask for everything, which is what every request used to get.
    tokens: wantAddresses ? sanitizeTokens(msg.tokens) : [],
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
  confirmPassword: c.confirmPassword?.index ?? null,
  otp: c.otp?.index ?? null,
});

/** The overlay asking what to draw. Only an extension page may ask. */
async function handleSession(msg, sender) {
  if (!isExtensionPage(sender)) return { candidates: [] };
  const session = sessions.get(asString(msg.sessionId, 64));
  if (!session) return { candidates: [] };
  if (session.kind === 'locked' || !vault || vault.locked) {
    // The menu needs to know whether a fingerprint is an option before it draws
    // its rows, so it goes out with the answer rather than after it.
    return { kind: 'locked', candidates: [], bio: await handleBioState() };
  }
  if (session.kind === 'signup') return { kind: 'signup', candidates: [] };

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
  let alts;
  if (session.kind === 'address') {
    const verdict = canFillAddress(session.frameHost, {
      pageHost: session.pageHost,
      frameProtocol: session.frameProtocol,
      allowInsecure: settings.allowInsecure,
    });
    if (!verdict.ok) return { ok: false, reason: verdict.reason };
    // Exactly the tokens the form has fields for, derived from the record —
    // a full name assembled from its parts, a country name from its code, a
    // street block from its lines. What the form did not ask for is not built
    // and does not travel.
    ({ values, alts } = valuesForTokens(record, session.tokens));
    if (!Object.keys(values).length) return { ok: false, reason: 'nothing-to-fill' };
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
    { type: MSG.FILL, kind: session.kind, values, alts },
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

/**
 * Put the manager somewhere visible.
 *
 * tabs.create is the floor of this whole arrangement: it needs no user gesture,
 * has nothing to anchor to, and cannot resolve while doing nothing — which is
 * how both openPopup() and openOptionsPage() managed to fail silently from an
 * overlay frame.
 */
async function handleOpenManager(_msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false };

  const url = browser.runtime.getURL('ui/manager.html');

  // Reuse a manager tab if one is already open, rather than stacking them up.
  const existing = (await browser.tabs.query({ url }).catch(() => []))[0];
  if (existing) {
    await browser.tabs.update(existing.id, { active: true });
    await browser.windows.update(existing.windowId, { focused: true }).catch(() => {});
    promptForUnlock();
    return { ok: true };
  }

  const tab = await browser.tabs.create({ url });
  // Remember where this came from. Sending someone to another tab to type a
  // password and leaving them there is most of why a sidebar was wanted in the
  // first place; the tab closes itself once the vault opens.
  if (sender.tab?.id !== undefined) unlockReturns.set(tab.id, sender.tab.id);
  return { ok: true, via: 'tab' };
}

/**
 * Ask whatever manager surface is already open to raise the fingerprint prompt.
 *
 * A manager that is opened fresh prompts on the way in, so this is for the two
 * cases where there is no way in: a tab that already existed and was merely
 * focused, and the sidebar, which is not a tab and so is never found by the
 * query above at all. Both are otherwise a locked gate with a button on it,
 * reached by someone who has already said what they want.
 *
 * Broadcast rather than aimed, because the sidebar has no address. Every other
 * extension page ignores it, and a manager that is not locked ignores it too.
 */
function promptForUnlock() {
  browser.runtime.sendMessage({ type: MSG.PROMPT_BIO }).catch(() => {
    // Nothing listening. Routine: the popup may have closed, and a manager tab
    // created a moment ago is not up yet -- and that one prompts by itself.
  });
}

/** Manager tabs opened purely to unlock, and the tab to return to after. */
const unlockReturns = new Map();

async function handleUnlocked(sender) {
  if (!isExtensionPage(sender)) return { ok: false };

  // A manager page unlocks the vault by calling into it directly rather than
  // through handleUnlock, so none of the things that normally follow an unlock
  // had happened: the timer had not started, the toolbar icon was still the
  // locked one, and every anchor already drawn on a page was still red.
  bumpAutolock();
  paintBadge();
  broadcastLockState();
  scheduleSync();
  await forkParkedConflicts();

  const managerTab = sender.tab?.id;
  if (managerTab === undefined || !unlockReturns.has(managerTab)) return { ok: true };

  const returnTo = unlockReturns.get(managerTab);
  unlockReturns.delete(managerTab);

  // Back to the page the person was actually on, then close the detour.
  await browser.tabs.update(returnTo, { active: true }).catch(() => {});
  await browser.tabs.remove(managerTab).catch(() => {});
  return { ok: true, returned: true };
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
/**
 * Which pending capture a message is talking about, and whether it may.
 *
 * The popup and the manager are trusted to mean the tab in front of them: they
 * are extension pages a page cannot reach. The toast is different — it is
 * web-accessible, so a hostile page can frame its own copy, and that copy would
 * satisfy every "is this an extension page" check made here. It therefore has
 * to quote the unguessable id issued with the offer, which reaches the real
 * toast by a postMessage the page cannot listen to.
 */
async function pendingFor(msg, sender) {
  // A framed extension page has a tab; the popup and the sidebar do not.
  const tabId =
    sender?.tab?.id ?? (await browser.tabs.query({ active: true, currentWindow: true }))[0]?.id;
  if (tabId === undefined) return { tabId: undefined, pending: null };

  const pending = pendingCaptures.get(tabId) ?? null;
  if (!pending) return { tabId, pending: null };

  const fromToast = sender?.url === browser.runtime.getURL('ext/toast.html');
  if (fromToast && asString(msg?.noticeId, 64) !== pending.noticeId) {
    return { tabId, pending: null };
  }
  return { tabId, pending };
}

/** What the toast in this tab should print. Never a secret — see toast.js. */
async function handleNoticeState(msg, sender) {
  const { pending } = await pendingFor(msg, sender);
  if (!pending) return {};
  return {
    kind: pending.kind ?? 'login',
    host: pending.host,
    username: pending.username ?? '',
    update: Boolean(pending.existingId),
    summary: pending.kind === 'address' ? addressSummary(pending.address) : '',
    suggestedName: pending.suggestedName ?? '',
  };
}

async function handleSave(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  if (!vault || vault.locked) return { ok: false, reason: 'locked' };

  const { tabId, pending } = await pendingFor(msg, sender);
  const tab = tabId === undefined ? null : { id: tabId };
  if (!pending) return { ok: false, reason: 'nothing-pending' };

  let merged = false;
  if (pending.kind === 'address') {
    // Named by the user, never by the site it was typed into. An address
    // belongs to the person: one "Home" is then offered on every checkout,
    // which is the whole difference between an address and a login. Titling
    // these with the host produced a vault full of near-identical addresses
    // called after shops.
    const title =
      asString(msg.title, 60).trim() ||
      pending.suggestedName ||
      addressSummary(pending.address) ||
      'Address';

    // Saving under a name that already exists updates that address rather than
    // adding a second one beside it. Otherwise "Home" becomes "Home", "Home",
    // "Home" — and there is no way to tell from the menu which is current.
    const existing = addressesFor(vault.list()).find(
      (r) => (r.title ?? '').toLowerCase() === title.toLowerCase(),
    );
    if (existing) {
      await vault.update(existing.id, { ...pending.address, title });
      merged = true;
    } else {
      await vault.add({ type: 'address', title, ...pending.address });
    }
  } else if (pending.existingId && vault.get(pending.existingId)) {
    // The old password is kept in the record's history by applyPatch, so a
    // capture that turns out to be a typo is recoverable.
    const target = vault.get(pending.existingId);
    const patch = { password: pending.password };
    if (target.provisional) {
      // Saving over a provisional entry is the sign-up finishing by another
      // route: the username arrives with it, and the entry stops being a
      // half-made one.
      patch.username = pending.username || target.username || '';
      patch.provisional = false;
    }
    await vault.update(pending.existingId, patch);
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
  clearCaptureNotice(tab.id);
  paintBadge();
  bumpAutolock();
  return { ok: true, merged };
}

async function handleDiscard(msg, sender) {
  const { tabId, pending } = await pendingFor(msg, sender);
  if (tabId === undefined || !pending) return { ok: true };
  pendingCaptures.delete(tabId);
  clearCaptureNotice(tabId);
  paintBadge();
  return { ok: true };
}

/**
 * "Never for this site": discard the offer and stop making them for its site.
 *
 * The site is taken from the pending capture the background itself recorded,
 * never from the message — the toast is web-accessible, so what it may do is
 * gated the same way its Save is (pendingFor checks the notice id), and what
 * it says is limited to naming an offer that really exists. The list lands in
 * settings, not the vault: see the neverSites note at the top.
 *
 * The answer names the site so the toast can say exactly what was silenced —
 * a person on login.example.com has just silenced example.com entire, and
 * finding that out later, from the site's sign-in form failing to prompt,
 * would read as breakage.
 */
async function handleNever(msg, sender) {
  // Extension pages only, like SAVE: this writes a durable preference, and a
  // content script sharing a DOM with a hostile page must not be able to
  // silence the site it sits on. (The toast qualifies — it is our document —
  // and pendingFor still demands its notice id.)
  if (!isExtensionPage(sender)) return { ok: false };
  const { tabId, pending } = await pendingFor(msg, sender);
  if (tabId === undefined || !pending) return { ok: false };

  const site = siteKey(pending.host);
  if (site && !(settings.neverSites ?? []).includes(site)) {
    settings.neverSites = [...(settings.neverSites ?? []), site];
    await persistSettings();
  }
  pendingCaptures.delete(tabId);
  clearCaptureNotice(tabId);
  paintBadge();
  return { ok: true, site };
}

/** The address tokens a page claims to have fields for, kept honest. */
const sanitizeTokens = (raw) => {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const token of raw.slice(0, 64)) {
    const clean = asString(token, 32);
    if (ADDRESS_TOKENS.has(clean) && !out.includes(clean)) out.push(clean);
  }
  return out;
};

/**
 * A generated password is stored before it is filled.
 *
 * It used to go to the page and nowhere else until the user pressed Save — and
 * the offer to save could die with the navigation the submit causes, or with
 * the tab, or with an idle lock. Every one of those left the site holding a
 * password nobody knew. So the vault now keeps it as a provisional entry the
 * moment it exists; submitting the form completes the entry with the username
 * (see handleCapture), and a sign-up abandoned halfway leaves a record the
 * person can see and delete rather than a password that exists nowhere.
 */
async function handleGenerate(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  // Locking clears the sessions, so this is belt and braces — but a password
  // that cannot be saved must never be filled, so the belt stays.
  if (!vault || vault.locked) return { ok: false, reason: 'locked' };
  const session = sessions.get(asString(msg.sessionId, 64));
  if (!session) return { ok: false };

  const password = generate({ length: 20 });
  await keepGenerated(vault, {
    host: session.frameHost,
    url: session.frameHost ? `${session.frameProtocol ?? 'https:'}//${session.frameHost}` : '',
    password,
  });
  await persistVault();
  await browser.tabs.sendMessage(
    session.tabId,
    { type: MSG.FILL, kind: 'generated', values: { password } },
    { frameId: session.frameId },
  );
  return { ok: true };
}

/**
 * The unit "never for this site" works in: the registrable domain, the same
 * unit every match decision uses — silencing login.example.com and being asked
 * again by www.example.com would read as the button not working. An IP is its
 * own site, and a host that IS a public suffix falls back to itself.
 */
const siteKey = (host) => registrableDomain(host) ?? normaliseHost(host);

const neverForSite = (host) => (settings.neverSites ?? []).includes(siteKey(host));

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

  if (msg.kind === 'address') {
    // "Never for this site" silences the whole toast for the site, addresses
    // included: the person who silenced their NAS's admin pages meant the
    // asking, not one kind of it.
    if (neverForSite(origin.frameHost)) return { ok: false };
    return captureAddress(msg, origin);
  }

  const username = asString(msg.username, 256);
  const password = asString(msg.password, 1024);
  if (!password) return { ok: false };

  // A password box holding nothing but mask characters — the placeholder a
  // site shows for a value already set. Stored, it becomes an entry that shows
  // dots before Reveal and asterisks after, which reads as a broken button
  // rather than as an empty password (see plausiblePassword).
  //
  // Above the provisional branch, unlike the username check below it, and the
  // asymmetry is load-bearing: that branch is entered only when the page's
  // password IS the one our generator produced, and the generator cannot
  // produce a run of asterisks. So nothing generated is at risk here, while
  // leaving the check until after it would let a mask string be written over
  // a real record's password by the overwritable path.
  if (!plausiblePassword(password)) return { ok: false };

  const { forHost, candidate, overwritable, provisional } = captureTarget(
    vault.list(),
    origin.frameHost,
    username,
  );

  // The password came out of our own generator and is already saved as a
  // provisional entry (see handleGenerate). This submit is the missing half —
  // the username it was generated for — so the record is completed on the
  // spot, with nothing to offer and nothing that can be lost by not pressing
  // Save on a toast the navigation is about to kill.
  if (provisional && provisional.password === password) {
    // Unless this site already has an entry that the password belongs on.
    //
    // Generating on a change-password form is a rotation, not a sign-up: the
    // account exists and so does its record. Completing the provisional entry
    // regardless left two rows with the same title, one holding the password
    // just rotated away, distinguishable only by a date in the detail pane —
    // which is the "which copy is current" drift this program exists to end,
    // reproduced inside a single machine on the most ordinary task there is.
    //
    // So the real entry takes the new password, keeping its username, its
    // sites and its history, and the scratch entry that was standing in for it
    // goes.
    if (overwritable && overwritable.id !== provisional.id) {
      await vault.update(overwritable.id, { password });
      await vault.remove(provisional.id);
      await persistVault();
      pendingCaptures.delete(origin.tabId);
      clearCaptureNotice(origin.tabId);
      paintBadge();
      return { ok: true, merged: true };
    }
    // Not without a look at the username first: on a page like the one below,
    // the field the classifier picked can hold a port number, and completing
    // the record with "14" is worse than leaving it provisional — the entry
    // stays visible either way, but only one of them carries rubbish forward.
    await completeGenerated(vault, provisional, plausibleUsername(username) ? username : '');
    await persistVault();
    pendingCaptures.delete(origin.tabId);
    clearCaptureNotice(origin.tabId);
    paintBadge();
    return { ok: true };
  }

  // A username that cannot be one — bare digits, seen offered as "Save 14 for
  // 10.0.0.214?" on the TrueNAS SCALE UI, where numeric settings share a form
  // with password boxes. No offer is made: an offer with obvious rubbish in it
  // teaches people to dismiss the toast unread, which costs more than the rare
  // all-digit account id it declines to capture (see plausibleUsername).
  // Deliberately below the provisional branch — a password from our own
  // generator is already saved, and the completion above must keep running.
  if (!plausibleUsername(username)) return { ok: false };

  // A site the person told us to stop asking about. Placed below the
  // provisional branch, and that placement is the safety property: a GENERATED
  // password was saved the moment it existed (keepGenerated) and its record
  // was just completed above, so this block only ever declines to offer a
  // password typed by hand — which is still in the person's head and on the
  // page. A preference set weeks ago must never be what loses a password
  // that exists nowhere else.
  if (neverForSite(origin.frameHost)) return { ok: false };

  // Updating in place is only offered for an entry that belongs to this site
  // and no other.
  //
  // An entry matches on any of its addresses, which is right — one account can
  // live on two domains. But it means an entry naming both this site and
  // somewhere else can be the one a capture lands on, and the capture writes a
  // password that was typed *here* into a record that also fills *there*. That
  // was only ever a self-inflicted wound until import arrived; now the entry
  // can come from a file, and a crafted one pairs the real site with the
  // attacker's and waits for the password to be filled in for them.
  //
  // A wider entry is not refused, only not silently overwritten: the password
  // is offered as a new entry scoped to this site, which costs a duplicate to
  // tidy and cannot cost the password.
  //
  // A provisional entry is the other legitimate landing spot: the person
  // generated a password here, then typed a different one before submitting.
  // Offering to update the half-made entry beats standing up a duplicate next
  // to it — and it is ours, made with exactly one URL, so it cannot carry the
  // password anywhere else.
  const existing = overwritable ?? provisional;

  // Nothing to learn if this host already has this exact password on file. The
  // username is only required to match when there was one to see: the second
  // page of a two-step sign-in has no username box at all, so insisting on it
  // there turned every such sign-in into an offer to save a duplicate.
  // Deliberately `candidate` and not `existing`: an entry that already holds
  // this exact password is nothing to learn from, whatever else it names, and
  // asking again would be the "it keeps offering to save a password I did not
  // change" complaint by another route.
  const alreadyKnown = candidate
    ? candidate.password === password
    : !username && forHost.some((r) => r.password === password);

  if (alreadyKnown) {
    // Nothing new — and anything still pending for this tab is now stale. A
    // leftover offer looks identical to a fresh one, which is how "it asks to
    // update a password I did not change" happens.
    pendingCaptures.delete(origin.tabId);
    clearCaptureNotice(origin.tabId);
    paintBadge();
    return { ok: false };
  }

  pendingCaptures.set(origin.tabId, {
    host: origin.frameHost,
    url: `${origin.frameProtocol}//${origin.frameHost}`,
    username,
    password,
    existingId: existing?.id ?? null,
    noticeId: newSessionId(),
  });
  paintBadge();
  announceCapture(origin.tabId, 'login');
  return { ok: true };
}

/**
 * An address typed into a checkout, offered for keeping.
 *
 * Only the WHATWG tokens are taken, and only from a page that already sent a
 * plausible set of them; anything else in the message is ignored rather than
 * merged into a record. What arrives is in the page's shape and is converted
 * into the record's — a full name split into parts, a street block cut into
 * lines, a country name resolved to its code — so that what comes back out is
 * answerable in whatever shape the *next* site asks for.
 */
function captureAddress(msg, origin) {
  const raw = {};
  if (msg.address && typeof msg.address === 'object') {
    for (const [key, value] of Object.entries(msg.address)) {
      if (ADDRESS_TOKENS.has(key)) raw[key] = asString(value, 256);
    }
  }
  const incoming = normalizeCaptured(raw);

  // Two structural fields. A name and an email off a newsletter box is not an
  // address, however many boxes it happened to have.
  if (!isAddressish(incoming)) return { ok: false };

  // Already stored, allowing for the ways a form rewrites a value on the way
  // through — see matchesStored.
  const known = addressesFor(vault.list()).some((r) => matchesStored(r, incoming));
  if (known) {
    pendingCaptures.delete(origin.tabId);
    clearCaptureNotice(origin.tabId);
    paintBadge();
    return { ok: false };
  }

  pendingCaptures.set(origin.tabId, {
    kind: 'address',
    host: origin.frameHost,
    address: incoming,
    // A starting point for the name, never the final word — the popup offers it
    // in an editable box, and "Home" is the placeholder. The site is not a
    // candidate: an address is not a per-site thing, and naming one after the
    // shop it was first typed into is what made a vault full of addresses
    // called after shops.
    suggestedName: suggestAddressName(incoming),
    noticeId: newSessionId(),
  });
  paintBadge();
  announceCapture(origin.tabId, 'address');
  return { ok: true };
}

/**
 * A plausible name for a newly seen address.
 *
 * The town, which is the part of an address a person is most likely to think of
 * it by after "home" and "work". Failing that the street, and failing that
 * nothing at all — an empty box with a placeholder is more honest than a name
 * nobody chose.
 */
const suggestAddressName = (a) =>
  asString(a['address-level2'] || a['address-line1'] || '', 60).trim();

// ---- settings ---------------------------------------------------------------
//
// Read and written one field at a time, through an allow-list. The settings
// object also holds the device key the sync server authenticates us with, and
// that never leaves here: the manager is told *whether* this machine is
// enrolled, never with what.

const MIN_AUTOLOCK_MS = 60 * 1000;
const MAX_AUTOLOCK_MS = 24 * 60 * 60 * 1000;

/**
 * What this machine calls itself when enrolling.
 *
 * The server lists devices by this, and "device 3" tells nobody which machine
 * to stop trusting. The platform is the most it can honestly know.
 */
async function deviceName() {
  const os = await browser.runtime
    .getPlatformInfo()
    .then((i) => i.os)
    .catch(() => '');
  return { mac: 'mac', win: 'windows', linux: 'linux' }[os] ?? 'browser';
}

/**
 * Is there already a vault on this machine? Asked of STORAGE, not of the
 * in-memory `vault`, and the difference is the whole point: the memory is
 * blank while boot()'s read is in flight, and blank again if that read ever
 * fails — and both are exactly the moments a gate wrongly offering "create a
 * vault" gets a password typed into it. An overwrite here is every record
 * gone, so the one check that decides it goes to the copy that would be
 * destroyed.
 */
const vaultOnDisk = async () => Boolean(vault || (await store.read()));

/**
 * Create the very first vault on this machine — in this realm, and refusing to
 * be anything but the first.
 *
 * In this realm: the manager used to run Vault.create itself and hand the
 * instance over. The background then held an object owned by the manager
 * document, and the moment that document went away — tab closed, sidebar
 * closed, a navigation — Firefox nuked its compartment and the very next
 * `vault.locked` (the badge repaint on tabs.onRemoved, as it happened) threw
 * "can't access dead object", permanently, until the background itself
 * restarted. Built here, the vault lives exactly as long as the background
 * does. Only the password crosses, as a string, and it lives here only for
 * the length of this call — the same lifetime and the same callers as
 * UNLOCK's, gated by the same isExtensionPage.
 *
 * Refusing to be anything but the first: see vaultOnDisk. Deliberately
 * destroying a vault to start over is a real thing to want, and it still has
 * no path (ARCHITECTURE.md §10) — this handler must never become one by
 * accident.
 */
async function handleSetup(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false, reason: 'error' };
  if (await vaultOnDisk()) {
    return { ok: false, reason: 'already-a-vault', message: 'There is already a vault on this machine.' };
  }

  const password = asString(msg.password, 1024);
  if (!password) return { ok: false, reason: 'no-password', message: 'Enter a master password.' };

  vault = await Vault.create({ password });
  await persistVault();

  // The same duties as an unlock, because a fresh vault is an unlocked one:
  // the timer starts, the toolbar icon goes green, anchors already drawn on
  // open pages hear about it, and the sync clock starts ticking.
  bumpAutolock();
  paintBadge();
  broadcastLockState();
  scheduleSync();
  return { ok: true };
}

/**
 * Adopt the vault a configured server is already carrying.
 *
 * Only ever the first vault on a machine: replacing an existing one would throw
 * away whatever it holds, and no path in the interface asks for that. The
 * refusal is explicit rather than implied by an overwrite — and it is asked of
 * storage, not of memory, for the reason vaultOnDisk gives.
 */
async function handleJoin(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  if (await vaultOnDisk()) {
    return { ok: false, reason: 'already-a-vault', message: 'There is already a vault on this machine.' };
  }

  const password = asString(msg.password, 1024);
  if (!password) return { ok: false, reason: 'no-password', message: 'Enter the master password.' };

  const c = client();
  if (!c) {
    return {
      ok: false,
      reason: 'not-configured',
      message: 'Set the server address and an enrolment code first.',
    };
  }

  let joined;
  try {
    joined = await joinVault({ client: c, password, Vault, floor: settings.enrolFloor ?? 0 });
  } catch (err) {
    // joinVault tells "no vault there" apart from "that password does not open
    // it" apart from "this server has been rolled back below what the
    // enrolment code vouches for", and all three are worth more than a bare
    // failure.
    return { ok: false, reason: err?.code ?? 'error', message: String(err?.message ?? err) };
  }

  vault = joined;
  // A joined vault starts from nothing and pulls everything, so its sync state
  // starts from nothing too — an inherited high-water mark from some earlier
  // configuration would refuse the very first pull as a rollback. The one
  // exception is deliberate: the floor off the enrolment code IS the join's
  // high-water mark, minted by an already-enrolled machine and carried here by
  // hand, and refusing a server below it is exactly what it is for.
  syncState = loadSyncState(null);
  syncState.highestSeq = Math.max(0, Math.floor(Number(settings.enrolFloor) || 0));
  await persistVault();
  await persistSettings();

  bumpAutolock();
  paintBadge();
  broadcastLockState();
  scheduleSync();

  // The records come down the ordinary path, so there is one route that moves
  // them rather than two.
  try {
    await handleSync();
  } catch {
    // Joined regardless: the vault is open and the next sync fetches. Reporting
    // a failure here would be wrong about what happened.
  }
  return { ok: true };
}

/**
 * Which machines are enrolled, and which one is this.
 *
 * `mine` is the difference between a list and a decision: revoking the wrong
 * row is how somebody locks themselves out of their own vault, and "linux"
 * three times over gives them no way to tell.
 */
/**
 * Forget what this machine believes it has already synced.
 *
 * For one situation, and it is worth being exact about which: the server was
 * rebuilt, restored from an older backup, or replaced. Its sequence then starts
 * lower than the number this machine has already seen, and the rollback guard
 * refuses every sync — correctly. That guard is what stops a rolled-back or
 * impostor server quietly resurrecting deleted records, so it does not get a
 * reset button sitting next to it on the off chance.
 *
 * What this discards is only the bookkeeping: which revision of each record was
 * last agreed with the server. The vault is untouched. The next sync therefore
 * treats every local record as new and pushes it, which is right for a server
 * that has lost its copy.
 *
 * What it cannot recover is anything that existed *only* on the server — a
 * record another machine wrote that this one never pulled. That is gone with
 * the server's data, and no amount of forgetting here brings it back.
 */
async function handleSyncForget(sender) {
  if (!isExtensionPage(sender)) return { ok: false };

  syncState = loadSyncState(null);
  await persistSettings();
  return { ok: true };
}

/**
 * Mint a one-time enrolment code for the next machine.
 *
 * The server prints a bootstrap code only while zero devices are enrolled.
 * After machine one, POST /v1/codes — a signed request only an enrolled
 * machine can make — is the only way to mint another, and until this handler
 * existed nothing in the extension ever called it: machines two and three
 * were permanently locked out, while the deployment guide described a mint
 * button that was never built.
 */
async function handleMintCode(sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  const c = client();
  if (!c) {
    return {
      ok: false,
      reason: 'not-configured',
      message:
        'No server is configured, or this machine is not enrolled. Fill in Server and Enrollment code above first.',
    };
  }

  try {
    const { code, ttlSeconds } = await c.mintCode();
    // The code the server minted, plus this machine's own high-water mark. The
    // suffix is what gives the joining machine a rollback floor before it has
    // any history of its own — the server cannot write it (the code travels by
    // hand) and cannot strip it (it never sees the pasted whole). A machine
    // that has never synced has no floor to vouch for, and appends none.
    return { ok: true, code: packEnrolCode(code, syncState.highestSeq), ttlSeconds };
  } catch (err) {
    if (err?.code === 'unauthorised') {
      // A 401 is what a revoked key returns, and it is also what a protocol
      // mismatch returns. /v1/health names the server's protocol without a
      // signature, so the two can be told apart here instead of both reading
      // as a credential problem.
      const check = await c.checkProtocol().catch(() => null);
      if (check?.ok === false && (check.reason === 'client-too-old' || check.reason === 'server-too-old')) {
        return {
          ok: false,
          reason: check.reason,
          message:
            `The server speaks protocol ${check.protocol} and this BENCpass speaks ${PROTOCOL}. ` +
            (check.reason === 'client-too-old' ? 'Update the extension.' : 'Update the server.'),
        };
      }
      return {
        ok: false,
        reason: 'unauthorised',
        message:
          "The server refused this machine's key. If this machine was revoked, enrol it again with a fresh code.",
      };
    }
    return { ok: false, reason: err?.code ?? 'error', message: String(err?.message ?? err) };
  }
}

async function handleDevices(sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  const c = client();
  if (!c) return { ok: false, reason: 'not-configured' };
  try {
    return { ok: true, devices: await c.devices(), mine: settings.deviceId };
  } catch (err) {
    return { ok: false, reason: err?.code ?? 'error', message: String(err?.message ?? err) };
  }
}

async function handleDeviceForget(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  const c = client();
  if (!c) return { ok: false, reason: 'not-configured' };

  const id = asString(msg.deviceId, 128);
  if (!id) return { ok: false, reason: 'no-device' };

  // Decided before the credential is cleared, or the comparison below is made
  // against the empty string it was just set to and always answers no.
  const self = id === settings.deviceId;

  try {
    await c.forgetDevice(id);
  } catch (err) {
    return { ok: false, reason: err?.code ?? 'error', message: String(err?.message ?? err) };
  }

  // Revoking this machine is allowed — it is how one about to be wiped bows
  // out — but it cannot then go on syncing with a key the server has dropped.
  // Clearing the credential turns the next sync into "no server set" rather
  // than a 401 that reads as something broken.
  if (self) {
    settings.deviceId = '';
    settings.deviceKey = '';
    await persistSettings();
  }
  return { ok: true, self };
}

async function handleDeviceRename(msg, sender) {
  if (!isExtensionPage(sender)) return { ok: false };
  const c = client();
  if (!c) return { ok: false, reason: 'not-configured' };

  const id = asString(msg.deviceId, 128);
  const name = asString(msg.name, 128);
  if (!id) return { ok: false, reason: 'no-device' };

  try {
    return { ok: true, name: await c.renameDevice(id, name) };
  } catch (err) {
    return { ok: false, reason: err?.code ?? 'error', message: String(err?.message ?? err) };
  }
}

async function handleSettingsGet() {
  return {
    endpoint: settings.endpoint,
    fallbackEndpoint: settings.fallbackEndpoint,
    lastSyncVia,
    autolockMinutes: Math.round((settings.autolockMs || AUTOLOCK_MS) / 60000),
    allowInsecure: Boolean(settings.allowInsecure),
    // Visible and editable in Settings, because "never" gets pressed in a
    // hurry and a decision that cannot be found cannot be undone.
    neverSites: [...(settings.neverSites ?? [])],
    // Enough to say "this machine is enrolled with the server" and no more.
    deviceId: settings.deviceId,
    enrolled: Boolean(settings.deviceId && settings.deviceKey),
    lastSync: lastSyncAt,
    // The last refusal a person needs to know about — tampering, a rollback, a
    // dropped write — held until a sync succeeds, because the background timer
    // that usually finds these reports to nobody.
    syncProblem: lastSyncProblem,
    version: browser.runtime.getManifest().version,
    records: vault && !vault.locked ? vault.list().length : null,
  };
}

/**
 * An address for the sync server, or a reason it will not do.
 *
 * The same rule the fill code applies to a page: plaintext is allowed to a
 * private host, because a LAN address cannot hold a public certificate, and
 * refused to anything else however convenient.
 */
function checkEndpoint(raw) {
  const endpoint = asString(raw, 512).trim().replace(/\/+$/, '');
  if (!endpoint) return { ok: true, endpoint: '' };
  let url;
  try {
    url = new URL(endpoint);
  } catch {
    return { ok: false, reason: 'bad-endpoint' };
  }
  if (url.protocol !== 'https:' && !isPrivateHost(url.hostname)) {
    return { ok: false, reason: 'insecure-endpoint' };
  }
  return { ok: true, endpoint };
}

async function handleSettingsSet(msg) {
  const patch = {};

  for (const [field, key] of [
    ['endpoint', 'endpoint'],
    ['fallbackEndpoint', 'fallbackEndpoint'],
  ]) {
    if (typeof msg[field] !== 'string') continue;
    const checked = checkEndpoint(msg[field]);
    if (!checked.ok) return { ok: false, reason: checked.reason, field };
    patch[key] = checked.endpoint;
  }

  if (msg.autolockMinutes !== undefined) {
    const ms = Number(msg.autolockMinutes) * 60000;
    if (!Number.isFinite(ms) || ms < MIN_AUTOLOCK_MS || ms > MAX_AUTOLOCK_MS) {
      return { ok: false, reason: 'bad-autolock' };
    }
    patch.autolockMs = ms;
  }

  if (msg.allowInsecure !== undefined) patch.allowInsecure = Boolean(msg.allowInsecure);

  // The whole list at once, because the manager's only edit is removal and a
  // remove-by-value message would race two open manager pages. Each entry is
  // reduced to the same key handleNever stores (a registrable domain, or the
  // bare host where none exists — an IP, a single-label intranet name), so a
  // pasted "https://www.example.com/" blocks what the button would have
  // blocked. Only entries that cannot name a host at all are dropped. Capped
  // like every other list a page can hand the background.
  if (Array.isArray(msg.neverSites)) {
    const clean = [];
    for (const raw of msg.neverSites.slice(0, 500)) {
      const s = asString(raw, 253);
      const host = hostOf(s) || normaliseHost(s);
      // Host characters only. A row that could never equal a real hostname is
      // not a preference, it is clutter that can never match anything.
      const site = /^[a-z0-9.:[\]-]+$/.test(host) ? siteKey(host) : '';
      if (site && !clean.includes(site)) clean.push(site);
    }
    patch.neverSites = clean;
  }

  // What the server hands out, in either of the two shapes a person can have.
  //
  // A bare code is what the server prints at startup and what an enrolled
  // device mints for the next one; it is redeemed here for a device id and key.
  // A `device-id:key` pair is the result of having redeemed one already.
  //
  // The box used to accept only the second while its own hint told people to
  // paste the first, so the code the server actually printed was rejected with
  // "an enrolment code looks like device-id:key" — and the answer was to go and
  // find curl.
  if (typeof msg.enrolment === 'string' && msg.enrolment.trim()) {
    const raw = asString(msg.enrolment, 512).trim();
    const parts = raw.split(/[:\s]+/).filter(Boolean);

    if (parts.length === 2) {
      patch.deviceId = parts[0];
      patch.deviceKey = parts[1];
    } else if (parts.length === 1) {
      const endpoint = patch.endpoint ?? settings.endpoint;
      const fallback = patch.fallbackEndpoint ?? settings.fallbackEndpoint;
      if (!endpoint && !fallback) return { ok: false, reason: 'no-endpoint-for-code' };
      try {
        const { deviceId, key, floor } = await SyncClient.enrol({
          endpoints: [endpoint, fallback].filter(Boolean),
          code: parts[0],
          name: await deviceName(),
        });
        patch.deviceId = deviceId;
        patch.deviceKey = btoa(String.fromCharCode(...key));
        // The floor the minting machine wrote into the code, kept for the join
        // (which resets sync state and needs it back) and adopted immediately:
        // never lowered, because a floor is a fact about the vault's history,
        // not a preference.
        patch.enrolFloor = floor;
        syncState.highestSeq = Math.max(syncState.highestSeq, floor);
      } catch (err) {
        return { ok: false, reason: err?.code === 'unreachable' ? 'unreachable' : 'bad-code' };
      }
    } else {
      return { ok: false, reason: 'bad-enrolment' };
    }
  }

  settings = { ...settings, ...patch };
  await persistSettings();
  // A changed auto-lock has to take effect now, not at the next unlock.
  if (patch.autolockMs !== undefined) bumpAutolock();
  return { ok: true, settings: await handleSettingsGet() };
}

// ---- biometric unlock -------------------------------------------------------
//
// Two independent wrappings of one vault key: the master password, and a random
// device secret the operating system holds behind a fingerprint. See the
// second-wrapping section of core/vault.js for the crypto and hosts/PROTOCOL.md
// for what the native host is and is not trusted with.
//
// Every one of these handlers has to survive there being no host at all, which
// is the normal case. Nothing here changes how the password path behaves.

async function handleBioState() {
  const os = await browser.runtime
    .getPlatformInfo()
    .then((info) => info.os)
    .catch(() => '');

  return {
    // Whether this vault carries the second wrapping, and which credential
    // derives it. Whether an authenticator is actually present is a question
    // only a document can ask — see webauthn.js — so the UI fills that in.
    enrolled: Boolean(vault?.hasBiometric),
    credentialId: settings.webauthnCredentialId ?? '',
    os,
  };
}

/**
 * The device secret as it arrives in a message, decoded and checked.
 *
 * It is derived in a document — WebAuthn will not run here — and crosses as
 * base64, because a string survives every messaging path without argument. The
 * bytes are recovered the same way the device key is above; anything that is
 * not a string, not base64, or not exactly the 32 bytes PRF produces comes back
 * null, which the callers turn into a refusal with a reason. Length is checked
 * here rather than left to the vault so that a truncated value never reaches
 * the crypto at all.
 */
function secretFrom(msg) {
  const encoded = asString(msg.secret, 128);
  if (!encoded) return null;
  let raw;
  try {
    raw = atob(encoded);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function handleBioEnrol(msg) {
  if (!vault) return { ok: false, reason: 'no-vault' };

  const password = asString(msg.password, 1024);
  if (!password) return { ok: false, reason: 'no-password' };

  const secret = secretFrom(msg);
  if (!secret) return { ok: false, reason: 'no-secret' };

  try {
    await vault.enrolBiometric(password, secret);
  } catch (err) {
    // A wrong password and a damaged vault get the same answer, for the same
    // reason the gate gives one — see unwrapVaultKey. Anything else carries its
    // message, because "error" on its own has now cost two round trips to
    // diagnose and told nobody anything either time.
    if (err?.code === 'unwrap-failed') return { ok: false, reason: 'bad-password' };
    console.error('BENCpass: enrolling the second wrapping failed', err);
    return { ok: false, reason: 'error', detail: String(err?.message ?? err) };
  }

  // Which credential to ask next time. Not a secret: it identifies the key, and
  // the key will not act without the fingerprint.
  settings.webauthnCredentialId = asString(msg.credentialId, 512);
  await persistVault();
  await persistSettings();
  return { ok: true };
}

async function handleBioUnlock(msg, sender) {
  if (!vault) return { ok: false, reason: 'no-vault' };
  if (!vault.locked) return { ok: true };
  if (!vault.hasBiometric) return { ok: false, reason: 'not-enrolled' };

  const secret = secretFrom(msg);
  if (!secret) return { ok: false, reason: 'no-secret' };

  try {
    await vault.unlockWithBiometricSecret(secret);
  } catch (err) {
    console.warn('BENCpass: the derived secret did not open this vault', err);
    // The keystore gave back something that does not open this vault. The
    // honest reading is that the two have drifted apart — a vault restored from
    // elsewhere, or a secret from a previous enrolment — and the way out is to
    // enrol again, so the stale wrapping goes.
    vault.forgetBiometric();
    await persistVault();
    return { ok: false, reason: 'stale-secret' };
  }

  bumpAutolock();
  paintBadge();
  broadcastLockState();
  scheduleSync();
  await forkParkedConflicts();

  // Asked from the menu on a login field: put that menu back, against the same
  // field, now with entries in it. Otherwise the fingerprint opens the vault
  // and leaves the person staring at the field they started at, none the wiser.
  if (sender?.tab?.id !== undefined) {
    browser.tabs
      .sendMessage(sender.tab.id, { type: MSG.DISMISS, open: true }, { frameId: sender.frameId ?? 0 })
      .catch(() => {});
  }
  return { ok: true };
}

async function handleBioForget() {
  if (!vault) return { ok: false, reason: 'no-vault' };
  vault.forgetBiometric();
  settings.webauthnCredentialId = '';
  await persistVault();
  await persistSettings();
  // The credential itself is left on the authenticator. Nothing can be done
  // about that from here — a passkey is removed in the operating system's own
  // settings — and it opens nothing once the wrapping it fitted is gone.
  return { ok: true };
}

const CAPTURE_NOTICE = 'bencpass-capture';

/**
 * Say out loud that there is something to save.
 *
 * A toast drawn into the page, because the two quieter signals both failed. The
 * badge on the toolbar icon is no use to someone not already looking for it,
 * and in Zen the chrome can be hidden entirely; the operating system's
 * notification never appeared once across weeks of use, swallowed by a
 * notification daemon or a focus setting, with no way to tell which from in
 * here. An iframe on our own origin is the one surface nothing else can
 * suppress.
 *
 * The badge stays as a fallback for the tab that has no content script — a
 * PDF viewer, a `view-source:` page — and the OS notification is tried last,
 * costing nothing when it works and nothing when it does not.
 */
async function announceCapture(tabId, kind) {
  try {
    await browser.tabs.sendMessage(tabId, {
      type: MSG.NOTICE,
      noticeId: pendingCaptures.get(tabId)?.noticeId,
      kind,
    });
    return;
  } catch {
    /* no content script in that tab; fall through to the OS notification */
  }
  osNotification(kind);
}

/** Last resort, and known to be unreliable. Never the only signal. */
function osNotification(kind) {
  if (!browser.notifications?.create) return;
  // try/catch as well as .catch(): create() can throw synchronously, which a
  // promise catch never sees — which is how this managed to fail in silence.
  try {
    browser.notifications
      .create(CAPTURE_NOTICE, {
        type: 'basic',
        iconUrl: browser.runtime.getURL('ext/icons/64.png'),
        title: kind === 'address' ? 'BENCpass — keep this address?' : 'BENCpass — save login?',
        message: 'Open BENCpass to keep it.',
      })
      .catch(() => {});
  } catch {
    /* nothing further to try */
  }
}

/** Take the offer off screen, wherever it is showing. */
function clearCaptureNotice(tabId) {
  browser.notifications?.clear?.(CAPTURE_NOTICE)?.catch?.(() => {});
  if (tabId === undefined) return;
  browser.tabs.sendMessage(tabId, { type: MSG.NOTICE, noticeId: null }).catch(() => {});
}

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
    // Sent with the rest rather than fetched separately, so the popup can put
    // the fingerprint in front of the password box on its first paint instead
    // of showing the password box and then replacing it.
    bio: await handleBioState(),
    host,
    endpoint: settings.endpoint,
    pending: pending
      ? {
          kind: pending.kind ?? 'login',
          host: pending.host,
          username: pending.username,
          summary: pending.kind === 'address' ? addressSummary(pending.address) : '',
          suggestedName: pending.suggestedName ?? '',
          update: Boolean(pending.existingId),
        }
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
    // The unlock may have adopted a header parked by an earlier sync — a
    // master password change made on another machine. Adoption happened in
    // memory; it must land on disk or a restart re-runs it (harmlessly, but
    // the disk should say what the vault says).
    if (vault.metaUpdated) {
      vault.metaUpdated = false;
      await persistVault();
    }
    bumpAutolock();
    paintBadge();
    broadcastLockState();
    scheduleSync();
    await forkParkedConflicts();
    // Named, never merely skipped. Tolerating an unreadable record is what
    // stops one fabricated envelope shutting the vault for good; saying
    // nothing about it would trade a lockout for a vault quietly holding less
    // than it did yesterday, which is the worse of the two.
    return { ok: true, damaged: vault.damaged.length };
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
  // Logins only. The popup's rows do exactly one thing — fill into the active
  // tab — and an address cannot go down that path: offering one produced a row
  // that failed with a reason the popup did not even have words for.
  return { results: vault.search(asString(msg.query, 256), 'login').map(publicCandidate) };
}

// ---- sync ------------------------------------------------------------------

/**
 * How long a working address stays the one tried first.
 *
 * The preference has to expire, or a laptop that synced once over Tailscale
 * would keep using it after coming home — correct, but slower, and it would
 * never notice the LAN had come back. It also has to last longer than the sync
 * interval, or it expires before it is ever used and nothing is remembered at
 * all. Fifteen minutes against a five-minute interval: two syncs go straight to
 * the address that works, the third re-checks.
 */
const PREFERRED_TTL_MS = 15 * 60 * 1000;

function client() {
  if (!settings.endpoint || !settings.deviceId || !settings.deviceKey) return null;

  const fresh = Date.now() - (settings.syncPreferredAt ?? 0) < PREFERRED_TTL_MS;
  return new SyncClient({
    // Both routes to the one server, in the order to try them.
    endpoints: [settings.endpoint, settings.fallbackEndpoint],
    deviceId: settings.deviceId,
    key: Uint8Array.from(atob(settings.deviceKey), (c) => c.charCodeAt(0)),
    // Carried across syncs, not just within one. Without this every sync
    // reopened with a connection to a LAN address that is not there when you
    // are out, and waited out the TCP timeout before trying the route that
    // works — every five minutes, all day.
    preferred: fresh ? settings.syncPreferred : '',
  });
}

/**
 * The data-collection permissions this add-on declares as optional, and whether
 * they are granted right now.
 *
 * Asked before every sync rather than once when the address was entered, and
 * that difference is the point: these are revocable in about:addons, and
 * Firefox does not enforce them at the network layer. Without this check,
 * turning them off there would leave the switches reading off while the vault
 * carried on syncing — which is exactly the contradiction the runtime prompt
 * was added to prevent, arrived at from the other end.
 *
 * The list is read from the manifest so it cannot drift from what is declared.
 */
async function mayTransmit() {
  const wanted =
    browser.runtime.getManifest()?.browser_specific_settings?.gecko
      ?.data_collection_permissions?.optional ?? [];
  if (!wanted.length) return true;
  try {
    return await browser.permissions.contains({ data_collection: wanted });
  } catch {
    // A build that does not know the key cannot be enforcing it either, and
    // strict_min_version means no such build can install this. Fail open only
    // here, where the alternative is refusing to sync on a browser that has no
    // opinion; the prompt itself fails closed.
    return true;
  }
}

async function handleSync() {
  const c = client();
  if (!c || !vault) return { ok: false, reason: 'not-configured' };
  if (!(await mayTransmit())) return { ok: false, reason: 'no-consent' };
  try {
    const result = await syncOnce(vault, c, syncState);
    lastSyncAt = Date.now();
    lastSyncVia = c.endpoint;
    lastSyncProblem = null;
    settings.syncPreferred = c.endpoint;
    settings.syncPreferredAt = lastSyncAt;
    await persistVault();
    await persistSettings();
    return { ok: true, ...result, conflicts: result.conflicts.length };
  } catch (err) {
    // A refusal that names an attack or a lost write outlives this call: the
    // background timer is usually the caller, and it reports to nobody.
    if (LOUD_REASONS.has(err.code)) {
      lastSyncProblem = { reason: err.code, message: err.message, at: Date.now() };
    }
    // A sync that stashed a header before failing still learned something a
    // restart must not forget; parked state lives in the vault JSON.
    await persistVault().catch(() => {});
    return { ok: false, reason: err.code ?? 'error', message: err.message };
  }
}

// Sync runs on a locked vault — the merge needs nothing inside the ciphertext —
// so this does not wait for an unlock, and locking does not stop it either.
//
// It used to wait, by accident: the only call was in handleUnlock, which only
// the popup's password form reaches. Unlocking through the manager gate, the
// sidebar, or a fingerprint never started the timer, so a machine that always
// unlocked one of those ways synced exactly never. Now boot() starts it, and
// the unlock and join paths re-assert it in case a later change makes boot
// conditional again.
//
// One interval, however many times this is called. The old version stacked a
// fresh setInterval per call — one more every popup unlock — until a day's use
// had the vault syncing every few seconds.
let syncTimer = null;

function scheduleSync() {
  clearInterval(syncTimer);
  syncTimer = setInterval(() => {
    // handleSync checks consent itself; this only avoids waking for a machine
    // with no server configured at all.
    if (client()) handleSync().catch(() => {});
  }, SYNC_INTERVAL_MS);
}

// ---- wiring ----------------------------------------------------------------

browser.tabs.onRemoved.addListener((tabId) => {
  pendingCaptures.delete(tabId);
  unlockReturns.delete(tabId);
  paintBadge();
});

/**
 * A generated password from the right-click menu, the way Firefox offers one.
 *
 * The `password` context means it only appears on password boxes, so it is not
 * clutter on every text field. `targetElementId` identifies the exact element
 * that was clicked; the content script resolves it with menus.getTargetElement,
 * which avoids guessing from focus — the right-click may not have moved it.
 */
browser.menus.create({
  id: 'bencpass-generate',
  title: 'Generate a password (BENCpass)',
  contexts: ['password'],
});

browser.menus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'bencpass-generate' || !tab?.id) return;

  // A locked vault cannot keep what this would generate, and a password that
  // is filled but kept nowhere is the worst outcome this extension can
  // produce — submit it, miss the one toast, and the site holds a password
  // nobody knows. So instead of filling, open the menu on the field, which
  // offers the way to unlock; this path used to fill regardless, with no lock
  // check at all.
  if (!vault || vault.locked) {
    browser.tabs
      .sendMessage(tab.id, { type: MSG.DISMISS, open: true }, { frameId: info.frameId ?? 0 })
      .catch(() => {});
    return;
  }

  const source = info.frameUrl ?? info.pageUrl ?? tab.url ?? '';
  const host = hostOf(source);
  let protocol = 'https:';
  try {
    protocol = new URL(source).protocol;
  } catch {
    /* left as https:, same stricter assumption as originOf */
  }

  const password = generate({ length: 20 });
  // Kept before it is filled, same as the menu path — see handleGenerate.
  await keepGenerated(vault, { host, url: host ? `${protocol}//${host}` : '', password });
  await persistVault();

  await browser.tabs
    .sendMessage(
      tab.id,
      {
        type: MSG.FILL_TARGET,
        targetElementId: info.targetElementId,
        values: { password },
      },
      { frameId: info.frameId ?? 0 },
    )
    .catch(() => {});
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
  // There is deliberately no setVault. There was one, and the manager used it
  // to hand over a Vault it had built during first-run setup — an object owned
  // by the manager document, which Firefox turned into a dead-object wrapper
  // the moment that document closed. Every `vault.locked` after that threw,
  // until the background itself was restarted. A vault enters this variable
  // three ways — boot() from storage, handleSetup, handleJoin — and all three
  // construct it in this realm. Keep it that way.
  //
  // Settled before any decision is read off it: boot()'s storage read is
  // async, and a page that reads `vault` before it lands sees "no vault" on a
  // machine that has one. The manager awaits this before it offers anything.
  get ready() {
    return ready;
  },
  // Auto-lock lives here and only here. Every manager page — the tab, the
  // sidebar, and any other copy open at the time — shares this one vault, so a
  // timer per page meant the earliest of them decided for all of them. A page
  // sitting on the gate had never started its clock, so the moment the vault
  // opened anywhere it read as overdue and shut it again within the second.
  get autolockAt() {
    return autolockAt;
  },
  bump: bumpAutolock,
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

// Held, not just called: `ready` is what the message dispatcher and the
// manager wait on before believing anything about the vault. If boot fails,
// every one of them fails with the real reason instead of proceeding on a
// blank memory — a background that cannot read its own storage must not be
// mistaken for a machine with no vault.
const ready = boot();
ready.catch((err) => console.error('BENCpass: boot failed', err));
