// The message contract between the content script, the overlay, the popup and
// the background page.
//
// The single most important rule in the extension is written down here:
//
//   THE CONTENT SCRIPT NEVER RECEIVES A PASSWORD IT DID NOT ALREADY HAVE.
//
// A content script shares a process and a DOM with a hostile page. It is the
// least trusted part of this codebase. So it is told what entries *exist* for
// its frame — titles and usernames, enough to draw a menu — and a secret only
// ever crosses to it as the single value being filled, after the user has
// picked an entry, and after the background has re-derived the frame's origin
// from `sender` rather than believing anything the frame claimed about itself.

export const MSG = Object.freeze({
  // content -> background
  DESCRIBE: 'describe', // "here are my fields, what are they?"
  CANDIDATES: 'candidates', // "what entries exist for this frame?"
  CAPTURE: 'capture', // "the user submitted these credentials"

  // overlay/popup -> background
  SESSION: 'session', // "what is in the menu for this session?"
  OPEN_MANAGER: 'open-manager', // "put the manager somewhere I can see it"
  UNLOCKED: 'unlocked', // "the manager just unlocked the vault"
  CHOOSE: 'choose', // "the user picked this entry"
  GENERATE: 'generate', // "make a password for this field"
  CLOSE: 'close',

  // background -> content
  FILL: 'fill', // "put these values in these fields"
  DISMISS: 'dismiss',
  LOCKSTATE: 'lockstate', // "the vault locked or unlocked; redraw"

  // popup -> background
  STATE: 'state',
  SAVE: 'save', // "keep the credentials I just submitted"
  DISCARD: 'discard',
  UNLOCK: 'unlock',
  LOCK: 'lock',
  SEARCH: 'search',
  SYNC: 'sync',
});

/**
 * A candidate as the content script and overlay are allowed to see it.
 *
 * Note what is absent. There is no password, no notes, no TOTP secret. If a
 * field is ever added here, ask first whether a hostile page reading it would
 * matter — because on a compromised site, it will.
 */
export function publicCandidate(record) {
  return {
    id: record.id,
    title: record.title ?? '',
    username: record.username ?? '',
    type: record.type ?? 'login',
  };
}

export function publicAddress(record) {
  return {
    id: record.id,
    title: record.title ?? '',
    summary: [record['address-line1'], record['address-level2'], record['postal-code']]
      .filter(Boolean)
      .join(', '),
    type: 'address',
  };
}

/**
 * Reject anything that is not a plain, shallow, JSON-ish message.
 *
 * Messages arrive from content scripts running inside pages we do not control.
 * Everything is treated as untrusted input: unknown types are dropped, and the
 * fields that matter are read with explicit coercion rather than spread into
 * something that then gets used as an options object.
 */
export function isMessage(m) {
  return (
    m !== null &&
    typeof m === 'object' &&
    typeof m.type === 'string' &&
    Object.values(MSG).includes(m.type)
  );
}

export const asString = (v, max = 4096) =>
  typeof v === 'string' ? v.slice(0, max) : '';

export const asId = (v) =>
  typeof v === 'string' && /^[0-9a-f-]{1,64}$/i.test(v) ? v : null;
