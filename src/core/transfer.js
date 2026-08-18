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

import { LOGIN, ADDRESS, TYPES, newRecord } from './model.js';

export const EXPORT_FORMAT = 'bencpass-export';
export const EXPORT_VERSION = 1;

// ---- out --------------------------------------------------------------------

/**
 * The whole vault as JSON: both record types, every field, no loss.
 *
 * This is the format to keep. The CSV below is for handing to another program,
 * and it silently drops everything a spreadsheet has no column for.
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
      records: records.map(strip),
    },
    null,
    2,
  )}\n`;
}

/** Drop the bookkeeping that means nothing outside the vault it came from. */
function strip(record) {
  const { history, ...rest } = record;
  return rest;
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
 * Strict about the envelope and forgiving about the contents: a file that is
 * not one of ours should say so rather than half-importing, while a record from
 * a newer version missing a field this one knows about should still arrive.
 */
export function fromJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TransferError('That file is not JSON.', 'not-json');
  }

  const list = Array.isArray(parsed) ? parsed : parsed?.records;
  if (!Array.isArray(list)) {
    throw new TransferError('That JSON does not look like a BENCpass export.', 'not-ours');
  }
  return list.map(recordFrom).filter(Boolean);
}

function recordFrom(raw, now = Date.now()) {
  if (!raw || typeof raw !== 'object') return null;
  const type = TYPES.includes(raw.type) ? raw.type : LOGIN;

  if (type === ADDRESS) {
    return newRecord({ ...raw, type: ADDRESS }, now);
  }

  const urls = Array.isArray(raw.urls) ? raw.urls.filter((u) => typeof u === 'string') : [];
  const rec = newRecord(
    {
      type: LOGIN,
      title: str(raw.title),
      username: str(raw.username),
      password: str(raw.password),
      notes: str(raw.notes),
      totp: str(raw.totp),
      urls,
    },
    now,
  );
  return empty(rec) ? null : rec;
}

const str = (v) => (typeof v === 'string' ? v : '');

/** Nothing worth keeping: no secret, no account, nowhere it applies. */
const empty = (r) => !r.password && !r.username && !r.urls.length && !r.notes;

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
  const rows = parseCsv(text);
  if (!rows.length) throw new TransferError('That file has no rows.', 'empty');

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
    const cell = (i) => (i >= 0 && i < row.length ? row[i].trim() : '');

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
