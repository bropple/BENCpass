// Getting passwords in, and getting them out again.
//
// The way out matters more than it looks. Someone running BENCpass without a
// server has exactly one copy of their vault, inside one browser profile, and
// a profile is not a thing people back up on purpose. Without an export, losing
// it loses everything — so this is a safety feature wearing the clothes of an
// interoperability one.
//
// The way in matters because the point of this project is to replace the
// browser's own manager, and nobody moves anywhere they cannot bring their
// passwords with them.
//
// Both directions handle plaintext, which is the one place in this codebase
// where that is true on purpose. Nothing here writes a file or reads one: it
// turns records into text and text into records, and the caller decides what to
// do with it. That keeps this file testable and keeps the decision about where
// plaintext goes at the surface where a person can see it.

import { LOGIN, ADDRESS, TYPES, EMPTY_ADDRESS, HISTORY_MAX, newRecord } from './model.js';

export const EXPORT_FORMAT = 'bencpass-export';
export const EXPORT_VERSION = 1;

// Bounds on what will be read in.
//
// Not a defence against an attacker so much as against a mistake, but the
// effect is the same either way: every imported record costs an AES-GCM seal
// and the whole vault is written to storage afterwards, so a file with a
// million rows in it does not fail — it succeeds, slowly, having wedged the
// browser and filled the profile on the way. A file that is refused in a
// tenth of a second is a far better outcome than one that works after five
// minutes of a frozen interface.
//
// The numbers are set where a real vault is nowhere near them. Ten thousand
// logins is more than anyone has; the largest human password manager exports
// run to hundreds.
export const MAX_RECORDS = 10_000;
export const MAX_TEXT = 32 * 1024 * 1024; // characters of input
export const MAX_FIELD = 64 * 1024; // characters in any one field
export const MAX_URLS = 64; // sites on one login

// ---- out --------------------------------------------------------------------

/**
 * The whole vault as JSON: both record types, and every field that is yours.
 *
 * This is the format to keep. The CSV below is for handing to another program,
 * and it silently drops everything a spreadsheet has no column for.
 *
 * "No loss" would be too strong in one direction: importing this back builds
 * each record from the known field set, so custom fields and the timestamps —
 * created, updated, passwordChanged, and the use counts — are re-stamped at
 * import time rather than restored. That is deliberate, and it is why a record
 * arriving from a file cannot bring its own shape with it; but it means a
 * restore from JSON loses password ages, not that the export omits them.
 *
 * Password history goes out with everything else. It used to be stripped as
 * "bookkeeping", which quietly cut the safety net out of the safety copy: the
 * old passwords applyPatch keeps exist so a bad rotation is recoverable, and a
 * restore from this file was exactly the day someone would need them.
 */
export function toJson(records, now = Date.now()) {
  return `${JSON.stringify(
    {
      format: EXPORT_FORMAT,
      version: EXPORT_VERSION,
      exportedAt: new Date(now).toISOString(),
      // Stated inside the file as well as in the interface, because this will
      // be found later in a downloads folder by someone who has forgotten what
      // it is.
      warning: 'This file contains your passwords in plain text. Anyone who can read it can read them.',
      records,
    },
    null,
    2,
  )}\n`;
}

const CSV_COLUMNS = ['name', 'url', 'username', 'password', 'note'];

/**
 * Logins as CSV, in the shape the other managers read.
 *
 * Addresses are deliberately absent. They do not fit a row of five columns
 * without inventing a layout nothing else reads, and a file that claims to hold
 * the vault while quietly holding half of it is worse than one that says what
 * it is. Use the JSON for everything.
 */
export function toCsv(records) {
  const rows = records
    .filter((r) => r.type === LOGIN)
    .map((r) => [r.title ?? '', (r.urls ?? [])[0] ?? '', r.username ?? '', r.password ?? '', r.notes ?? '']);
  return [CSV_COLUMNS, ...rows].map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

// Quote when the value could otherwise change the shape of the row, and double
// any quote inside it. RFC 4180.
function csvCell(value) {
  const s = String(value ?? '');
  return /[",\r\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

// ---- in ---------------------------------------------------------------------

/**
 * Read our own JSON back.
 *
 * Strict about the *shape* and forgiving about everything else. What is
 * required is a `records` array — or a bare array, which is what several other
 * managers write. The `format` and `version` fields that `toJson` stamps are
 * deliberately not checked: they are there so a person finding the file later
 * can tell what it is, and refusing to import a vault because a header string
 * did not match would fail exactly the user who most needs the import to work.
 *
 * Being permissive here is safe because nothing is trusted on the way in.
 * `recordFrom` builds each record key by key from the known field set and
 * coerces every value with String(), so a file's own shape never becomes a
 * record's shape.
 */
export function fromJson(text) {
  checkSize(text);

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TransferError('That file is not JSON.', 'not-json');
  }

  const list = Array.isArray(parsed) ? parsed : parsed?.records;
  if (!Array.isArray(list)) {
    // The encrypted backup is the file a person is most likely to be holding on
    // the bad day, and it is the one this importer cannot read: it is sealed
    // envelopes, not records. "Does not look like an export" sent that person
    // away thinking the file was broken. Name it, and name the way through.
    if (Array.isArray(parsed?.envelopes) && parsed?.meta) {
      throw new TransferError(
        'That is an encrypted backup. Import reads plain exports, not sealed ones — ' +
          'open the backup with BENCpass Rescue, export JSON from there, and import that file.',
        'encrypted-backup',
      );
    }
    throw new TransferError('That JSON does not look like a BENCpass export.', 'not-ours');
  }
  checkCount(list.length);
  return list.map((r) => recordFrom(r)).filter(Boolean);
}

function recordFrom(raw, now = Date.now()) {
  if (!raw || typeof raw !== 'object') return null;
  const type = TYPES.includes(raw.type) ? raw.type : LOGIN;

  if (type === ADDRESS) {
    // Built key by key from the known field set rather than spread wholesale.
    // Spreading an imported object let anything the file carried through as an
    // own property of the record -- a `password` key on an address, a value
    // that is an object rather than a string -- and while every reader coerces
    // with String() so none of it can do harm, a record whose shape depends on
    // the file it arrived in is a thing to be reasoned about forever after.
    // Cheaper to not have it.
    const fields = { type: ADDRESS, title: str(raw.title), notes: str(raw.notes) };
    for (const key of Object.keys(EMPTY_ADDRESS)) {
      if (key in fields) continue;
      fields[key] = str(raw[key]);
    }
    const rec = newRecord(fields, now);
    return emptyAddress(rec) ? null : rec;
  }

  // Through `str` like every other field, and capped in number as well.
  // Filtering for strings and stopping there was the one way into a record
  // that skipped MAX_FIELD: a 200,000-character "url" imported intact, was
  // sealed into storage, re-sealed on every edit afterwards, and walked by the
  // matcher on every page load. Bounded by MAX_TEXT overall, so it was never
  // an escape — just the one field where the limit did not apply.
  const urls = Array.isArray(raw.urls)
    ? raw.urls.filter((u) => typeof u === 'string').slice(0, MAX_URLS).map(str)
    : [];
  const rec = newRecord(
    {
      type: LOGIN,
      title: str(raw.title),
      username: str(raw.username),
      password: str(raw.password),
      notes: str(raw.notes),
      totp: str(raw.totp),
      urls,
      history: historyFrom(raw.history),
    },
    now,
  );
  return empty(rec) ? null : rec;
}

const str = (v) => (typeof v === 'string' ? v.slice(0, MAX_FIELD) : '');

/**
 * Old passwords from a file, built entry by entry like everything else here.
 *
 * Restored rather than dropped because the file is the safety copy: the whole
 * point of applyPatch keeping old passwords is recovering from a bad rotation,
 * and the export-then-reimport path is exactly the day that matters. Only the
 * two known keys survive, and a `changed` that is not a finite number becomes
 * 0 — undated, never invented.
 */
function historyFrom(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((h) => h && typeof h === 'object' && typeof h.password === 'string' && h.password)
    .slice(0, HISTORY_MAX)
    .map((h) => ({
      password: str(h.password),
      changed: Number.isFinite(h.changed) ? h.changed : 0,
    }));
}

/** The file itself, before anything tries to make sense of it. */
function checkSize(text) {
  if (typeof text !== 'string') throw new TransferError('That file could not be read as text.', 'not-text');
  if (text.length > MAX_TEXT) {
    throw new TransferError(
      `That file is too large to import (over ${Math.round(MAX_TEXT / 1024 / 1024)} MB).`,
      'too-large',
    );
  }
}

function checkCount(n) {
  if (n > MAX_RECORDS) {
    throw new TransferError(
      `That file holds ${n} entries, more than the ${MAX_RECORDS} this will import at once.`,
      'too-many',
    );
  }
}

/** Nothing worth keeping: no secret, no account, nowhere it applies. */
const empty = (r) => !r.password && !r.username && !r.urls.length && !r.notes;

/**
 * An address with nothing in it.
 *
 * Worth its own check: a file of blank rows would otherwise import as a screen
 * of empty entries that each have to be deleted by hand.
 */
const emptyAddress = (r) => Object.keys(EMPTY_ADDRESS).every((k) => !String(r[k] ?? '').trim());

/**
 * Column names the other managers use, mapped to ours.
 *
 * One table rather than one importer per program. Firefox, Chrome, Bitwarden
 * and KeePass all export a row per login and differ mainly in what they call
 * the columns, so matching on names covers all of them and most of whatever
 * else someone arrives with.
 */
const ALIASES = {
  title: ['name', 'title', 'account', 'display name', 'entry'],
  url: ['url', 'login_uri', 'web site', 'website', 'login url', 'uri', 'hostname'],
  username: ['username', 'login name', 'login_username', 'user name', 'user', 'email'],
  password: ['password', 'login_password', 'pass'],
  notes: ['notes', 'note', 'comments', 'comment'],
  totp: ['totp', 'login_totp', 'otpauth', 'otp'],
};

/**
 * Read a CSV export from somewhere else.
 *
 * The header decides what each column means; position is never assumed, because
 * the four programs people arrive from order them four different ways.
 */
export function fromCsv(text, now = Date.now()) {
  checkSize(text);
  const rows = parseCsv(text);
  if (!rows.length) throw new TransferError('That file has no rows.', 'empty');
  checkCount(rows.length - 1);

  const header = rows[0].map((h) => h.trim().toLowerCase().replace(/^"|"$/g, ''));
  const at = {};
  for (const [field, names] of Object.entries(ALIASES)) {
    at[field] = header.findIndex((h) => names.includes(h));
  }

  if (at.password < 0 && at.username < 0) {
    throw new TransferError(
      'No username or password column found. The first row should name the columns.',
      'no-columns',
    );
  }

  const out = [];
  for (const row of rows.slice(1)) {
    if (!row.length || row.every((c) => c === '')) continue;
    // Capped here as well as in str(): the JSON path coerces every field
    // through that, and this one does not go near it.
    const cell = (i) => (i >= 0 && i < row.length ? row[i].trim().slice(0, MAX_FIELD) : '');

    const url = cell(at.url);
    const rec = newRecord(
      {
        type: LOGIN,
        // Falling back to the host keeps the list readable: a hundred entries
        // all titled "(untitled)" is not an import anybody can use.
        title: cell(at.title) || hostOf(url) || cell(at.username) || 'Imported',
        username: cell(at.username),
        password: cell(at.password),
        notes: cell(at.notes),
        totp: cell(at.totp),
        urls: url ? [url] : [],
      },
      now,
    );
    if (!empty(rec)) out.push(rec);
  }
  if (!out.length) throw new TransferError('No entries in that file.', 'empty');
  return out;
}

function hostOf(url) {
  if (!url) return '';
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

/**
 * CSV, including the parts people forget.
 *
 * Quoted fields may contain commas, newlines and doubled quotes, and real
 * exports contain all three — a password is exactly the kind of value that has
 * a comma in it. A split on commas loses those rows or, worse, imports them
 * shifted by a column, which puts a password in the notes field of the wrong
 * entry. So this is a character loop rather than a regex.
 */
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;

  // A BOM survives every round trip through Excel and would otherwise become
  // part of the first column's name, so the header match fails on a file that
  // looks perfectly correct.
  const s = text.replace(/^﻿/, '');

  for (let i = 0; i < s.length; i++) {
    const c = s[i];

    if (quoted) {
      if (c === '"') {
        if (s[i + 1] === '"') {
          cell += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        cell += c;
      }
      continue;
    }

    if (c === '"' && cell === '') {
      quoted = true;
    } else if (c === ',') {
      row.push(cell);
      cell = '';
    } else if (c === '\n' || c === '\r') {
      // \r\n is one ending, not two.
      if (c === '\r' && s[i + 1] === '\n') i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else {
      cell += c;
    }
  }

  // A file that does not end in a newline still ends in a row.
  if (cell !== '' || row.length) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

/** Which file was wrong, and why, in words that can go straight on screen. */
export class TransferError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'TransferError';
    this.code = code;
  }
}

/**
 * Pick the reader from the text itself rather than the file extension.
 *
 * People rename files, and a `.txt` full of JSON is still JSON.
 */
export function parse(text, now = Date.now()) {
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return fromJson(text);
  return fromCsv(text, now);
}
