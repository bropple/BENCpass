import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  toJson,
  toCsv,
  fromJson,
  fromCsv,
  parse,
  parseCsv,
  TransferError,
  MAX_RECORDS,
  MAX_FIELD,
  MAX_URLS,
} from '../src/core/transfer.js';
import { newRecord, LOGIN, ADDRESS } from '../src/core/model.js';

// The exports of the four programs people actually arrive from. Kept verbatim
// rather than tidied, because the whole job here is coping with what they emit.

const FIREFOX =
  '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n' +
  '"https://example.com","ben","hunter2",,"https://example.com","{abc}","1700000000000","0","1700000000000"\n';

const CHROME = 'name,url,username,password,note\nExample,https://example.com/login,ben,hunter2,\n';

const BITWARDEN =
  'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n' +
  ',,login,Example,a note,,0,https://example.com,ben,hunter2,\n';

const KEEPASS = '"Account","Login Name","Password","Web Site","Comments"\n"Example","ben","hunter2","https://example.com",""\n';

/** assert.throws does not hand back the error, and the code is the point here. */
function refused(fn) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof TransferError, `threw ${err?.name}, not TransferError`);
    return err;
  }
  assert.fail('expected a refusal, got none');
}

test('a Firefox export comes in', () => {
  const [r] = fromCsv(FIREFOX);
  assert.equal(r.type, LOGIN);
  assert.equal(r.username, 'ben');
  assert.equal(r.password, 'hunter2');
  assert.deepEqual(r.urls, ['https://example.com']);
  // Firefox has no name column, so the host stands in rather than nothing.
  assert.equal(r.title, 'example.com');
});

test('a Chrome export comes in', () => {
  const [r] = fromCsv(CHROME);
  assert.equal(r.title, 'Example');
  assert.equal(r.username, 'ben');
  assert.equal(r.password, 'hunter2');
});

test('a Bitwarden export comes in, columns in a different order', () => {
  const [r] = fromCsv(BITWARDEN);
  assert.equal(r.title, 'Example');
  assert.equal(r.username, 'ben');
  assert.equal(r.password, 'hunter2');
  assert.equal(r.notes, 'a note');
});

test('a KeePass export comes in, columns under different names', () => {
  const [r] = fromCsv(KEEPASS);
  assert.equal(r.title, 'Example');
  assert.equal(r.username, 'ben');
  assert.equal(r.password, 'hunter2');
  assert.deepEqual(r.urls, ['https://example.com']);
});

test('a password containing a comma survives, in the right column', () => {
  // The failure this guards against is not losing the row — it is importing it
  // shifted by one, which files a password under notes and looks like it worked.
  const csv = 'name,url,username,password,note\nExample,https://example.com,ben,"a,b,c",kept\n';
  const [r] = fromCsv(csv);
  assert.equal(r.password, 'a,b,c');
  assert.equal(r.notes, 'kept');
});

test('quotes and newlines inside a field survive', () => {
  const csv = 'name,url,username,password,note\nExample,https://example.com,ben,"say ""hi""","line one\nline two"\n';
  const [r] = fromCsv(csv);
  assert.equal(r.password, 'say "hi"');
  assert.equal(r.notes, 'line one\nline two');
});

test('a leading byte-order mark does not break the header', () => {
  // Excel writes one, and it would otherwise become part of the first column's
  // name — so every column matches except the one the BOM is glued to.
  const [r] = fromCsv('﻿name,url,username,password\nExample,https://example.com,ben,hunter2\n');
  assert.equal(r.title, 'Example');
  assert.equal(r.password, 'hunter2');
});

test('CRLF line endings are one ending, not two', () => {
  const rows = parseCsv('a,b\r\nc,d\r\n');
  assert.deepEqual(rows, [
    ['a', 'b'],
    ['c', 'd'],
  ]);
});

test('a last line with no newline is still a row', () => {
  assert.deepEqual(parseCsv('a,b\nc,d'), [
    ['a', 'b'],
    ['c', 'd'],
  ]);
});

test('blank rows are skipped rather than imported empty', () => {
  const csv = 'name,url,username,password\nExample,https://example.com,ben,hunter2\n,,,\n';
  assert.equal(fromCsv(csv).length, 1);
});

test('a file with no recognisable columns is refused by name', () => {
  const err = refused(() => fromCsv('alpha,beta\n1,2\n'));
  assert.equal(err.code, 'no-columns');
});

test('a file with a header and nothing else is refused', () => {
  const err = refused(() => fromCsv('name,url,username,password\n'));
  assert.equal(err.code, 'empty');
});

test('JSON that is not ours is refused rather than half-imported', () => {
  const err = refused(() => fromJson('{"hello":"world"}'));
  assert.equal(err.code, 'not-ours');
});

test('text that is not JSON at all says so', () => {
  const err = refused(() => fromJson('{not json'));
  assert.equal(err.code, 'not-json');
});

test('a vault survives the round trip through JSON', () => {
  const before = [
    newRecord({
      type: LOGIN,
      title: 'Example',
      username: 'ben',
      password: 'hunter2',
      notes: 'a note',
      totp: 'otpauth://totp/x',
      urls: ['https://example.com'],
    }),
    newRecord({
      type: ADDRESS,
      title: 'Home',
      'address-line1': '1 Test Street',
      'address-level2': 'Testville',
      'country': 'GB',
      'tel': '+441234567890',
    }),
  ];

  const after = fromJson(toJson(before));
  assert.equal(after.length, 2);

  const login = after.find((r) => r.type === LOGIN);
  assert.equal(login.password, 'hunter2');
  assert.equal(login.totp, 'otpauth://totp/x');
  assert.deepEqual(login.urls, ['https://example.com']);

  // Addresses have to survive too — they are the half a CSV cannot carry, so
  // JSON is the only way out for them.
  const address = after.find((r) => r.type === ADDRESS);
  assert.equal(address['address-line1'], '1 Test Street');
  assert.equal(address.country, 'GB');
  assert.equal(address.tel, '+441234567890');
});

test('the exported JSON says what it is, in the file', () => {
  const text = toJson([]);
  const parsed = JSON.parse(text);
  assert.equal(parsed.format, 'bencpass-export');
  assert.match(parsed.warning, /plain text/i);
});

test('CSV out is readable by CSV in', () => {
  const before = [
    newRecord({
      type: LOGIN,
      title: 'Example',
      username: 'ben',
      password: 'a,b"c',
      notes: 'multi\nline',
      urls: ['https://example.com'],
    }),
  ];
  const [after] = fromCsv(toCsv(before));
  assert.equal(after.title, 'Example');
  assert.equal(after.username, 'ben');
  assert.equal(after.password, 'a,b"c');
  assert.equal(after.notes, 'multi\nline');
});

test('CSV out leaves addresses behind rather than mangling them', () => {
  const csv = toCsv([
    newRecord({ type: LOGIN, title: 'Example', password: 'x' }),
    newRecord({ type: ADDRESS, title: 'Home', 'address-line1': '1 Test Street' }),
  ]);
  assert.equal(parseCsv(csv).length, 2); // header plus the one login
});

test('parse picks the reader from the text, not the file name', () => {
  assert.equal(parse(CHROME).length, 1);
  assert.equal(parse(toJson([newRecord({ type: LOGIN, title: 'x', password: 'y' })])).length, 1);
});

test('an imported record is a real record with fresh timestamps', () => {
  // Chrome's CSV carries no dates at all, so the import time is the only
  // honest stamp there is. (Where the file DOES carry dates — Firefox — they
  // are kept instead; the tests below pin that.)
  const now = 1_700_000_000_000;
  const [r] = fromCsv(CHROME, now);
  assert.equal(r.created, now);
  assert.equal(r.updated, now);
  assert.equal(r.passwordChanged, now);
  assert.equal(r.timesUsed, 0);
  assert.deepEqual(r.history, []);
});

test('a Firefox export keeps the dates it carried', () => {
  // "Which copy is the newest" is the question this program exists to answer,
  // and the importer used to flatten the only evidence: every imported record
  // claimed to have been created and changed at import time.
  const created = 1_600_000_000_000;
  const used = 1_650_000_000_000;
  const changed = 1_700_000_000_000;
  const csv =
    '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n' +
    `"https://example.com","ben","hunter2",,"https://example.com","{abc}","${created}","${used}","${changed}"\n`;

  const [r] = fromCsv(csv, changed + 1_000_000);
  assert.equal(r.created, created);
  assert.equal(r.lastUsed, used);
  assert.equal(r.passwordChanged, changed);
  // The nearest thing the file has to "last written".
  assert.equal(r.updated, changed);
});

test("Firefox's zeroes and blanks mean nothing, not January 1970", () => {
  // timeLastUsed is "0" for a login never filled; an empty cell says even
  // less. Both must fall back to the importer's own stamps, not become epoch.
  const now = 1_700_000_000_000;
  const [r] = fromCsv(FIREFOX.replace('"1700000000000","0","1700000000000"', '"0","0",""'), now);
  assert.equal(r.created, now);
  assert.equal(r.lastUsed, 0);
  assert.equal(r.passwordChanged, now);
});

test('a file that carries epoch seconds is not read as 1970', () => {
  // Firefox writes milliseconds; some tools write seconds. Read as
  // milliseconds, 1.7e9 is three weeks into 1970, and that record wins every
  // "oldest password" audit forever.
  const seconds = 1_600_000_000;
  const csv =
    'url,username,password,timeCreated,timePasswordChanged\n' +
    `https://example.com,ben,hunter2,${seconds},${seconds}\n`;
  const [r] = fromCsv(csv);
  assert.equal(r.created, seconds * 1000);
  assert.equal(r.passwordChanged, seconds * 1000);
});

test('timestamps survive the JSON round trip', () => {
  // The JSON export is the safety copy, and a restore from it is exactly the
  // day password ages matter. Re-stamping them at import re-dated every
  // restored record to today.
  const rec = newRecord(
    { type: LOGIN, title: 'Example', username: 'ben', password: 'p', urls: ['https://example.com'] },
    1_600_000_000_000,
  );
  rec.updated = 1_650_000_000_000;
  rec.lastUsed = 1_660_000_000_000;
  rec.timesUsed = 7;
  rec.passwordChanged = 1_640_000_000_000;

  const [after] = fromJson(toJson([rec]));
  assert.equal(after.created, 1_600_000_000_000);
  assert.equal(after.updated, 1_650_000_000_000);
  assert.equal(after.lastUsed, 1_660_000_000_000);
  assert.equal(after.timesUsed, 7);
  assert.equal(after.passwordChanged, 1_640_000_000_000);
});

test('a timestamp from a file has to be a number to survive', () => {
  // The importer builds records key by key precisely so a file cannot bring
  // its own shape in; the timestamps must not become the exception.
  const [r] = fromJson(
    JSON.stringify([
      {
        title: 'x',
        password: 'p',
        created: 'yesterday',
        updated: { evil: true },
        lastUsed: -5,
        timesUsed: 'lots',
        passwordChanged: null,
      },
    ]),
  );
  const now = Date.now();
  assert.ok(Math.abs(r.created - now) < 60_000);
  assert.ok(Math.abs(r.updated - now) < 60_000);
  assert.equal(r.lastUsed, 0);
  assert.equal(r.timesUsed, 0);
  assert.ok(Math.abs(r.passwordChanged - now) < 60_000);
});

// ---- hostile files ----------------------------------------------------------
//
// An import file is fully attacker-controlled the moment somebody can be talked
// into opening one. These are the attacks that class of input is for.

test('__proto__ in an imported file does not reach Object.prototype', () => {
  // The classic against anything that builds objects out of parsed JSON. Safe
  // here because both this module and newRecord use spread, which defines
  // properties rather than assigning them — so `__proto__` lands as an inert
  // own key. Safe by construction is still worth a test: the day someone
  // rewrites one of those spreads as an assignment, this is what notices.
  const attacks = [
    '{"records":[{"type":"address","__proto__":{"polluted":"yes"}}]}',
    '{"records":[{"type":"login","password":"x","__proto__":{"polluted":"yes"}}]}',
    '{"records":[{"type":"address","constructor":{"prototype":{"polluted":"yes"}}}]}',
    '[{"type":"login","password":"x","__proto__":{"polluted":"yes"}}]',
  ];
  for (const a of attacks) fromJson(a);

  assert.equal(Object.prototype.polluted, undefined);
  assert.equal({}.polluted, undefined);
});

test('an imported address keeps only address fields, as strings', () => {
  const [r] = fromJson(
    JSON.stringify({
      records: [
        {
          type: 'address',
          'address-line1': '1 Test Street',
          'title': { nope: true },
          'tel': 12345,
          'password': 'not an address field',
          'sneaky': 'nor this',
        },
      ],
    }),
  );

  // Everything downstream wraps values in String(), so a non-string could not
  // do harm — but a record whose shape depends on the file it arrived in is a
  // thing to reason about forever, and this is cheaper.
  assert.equal(r['address-line1'], '1 Test Street');
  assert.equal(typeof r.title, 'string');
  assert.equal(r.title, '');
  assert.equal(r.tel, '');
  assert.equal(r.password, undefined, 'a password key rode in on an address');
  assert.equal(r.sneaky, undefined, 'an unknown key rode in on an address');
});

test('an address with nothing in it is not imported', () => {
  const empty = JSON.stringify({ records: [{ type: 'address', 'address-line1': '   ' }] });
  assert.equal(fromJson(empty).length, 0);
});

test('a file with more entries than will be imported is refused, not started', () => {
  // The failure this prevents is not an error — it is success, slowly, after
  // one AES-GCM seal per row has frozen the interface and filled the profile.
  const rows = ['name,url,username,password'];
  for (let i = 0; i < MAX_RECORDS + 1; i++) rows.push(`n${i},https://example.com,u${i},p${i}`);
  const err = refused(() => fromCsv(rows.join('\n')));
  assert.equal(err.code, 'too-many');

  const many = { records: Array.from({ length: MAX_RECORDS + 1 }, () => ({ type: 'login', password: 'x' })) };
  assert.equal(refused(() => fromJson(JSON.stringify(many))).code, 'too-many');
});

test('a single enormous field is trimmed rather than stored whole', () => {
  const huge = 'a'.repeat(200_000);
  const [r] = fromCsv(`name,url,username,password\nx,https://example.com,ben,${huge}`);
  assert.ok(r.password.length < huge.length, 'the field was stored at full length');
});

test('something that is not text at all is refused by name', () => {
  assert.equal(refused(() => fromJson(null)).code, 'not-text');
  assert.equal(refused(() => fromCsv(undefined)).code, 'not-text');
});

test('a javascript: url cannot arrive as somewhere to fill', async () => {
  // It can be stored — the manager renders urls as text and never as an href —
  // but it must never match a site. That is the matcher's job, so this asserts
  // the two agree rather than trusting either alone.
  const { scoreUrl } = await import('../src/core/match.js');
  const [r] = fromJson(
    '{"records":[{"type":"login","password":"x","urls":["javascript:alert(1)"]}]}',
  );
  assert.deepEqual(r.urls, ['javascript:alert(1)']);
  assert.equal(scoreUrl('javascript:alert(1)', 'example.com'), 0);
});

test('a huge url cannot slip past the field cap', () => {
  // Every other field goes through `str`, which caps at MAX_FIELD. urls was
  // filtered for strings and nothing else, so one enormous entry imported
  // intact and was then sealed, re-sealed on every edit, and walked by the
  // matcher on every page load.
  const huge = 'https://example.com/' + 'a'.repeat(MAX_FIELD * 3);
  const [rec] = fromJson(
    JSON.stringify({ records: [{ type: 'login', title: 't', urls: [huge, ...Array(200).fill('https://b.example')] }] }),
  );
  assert.ok(rec.urls[0].length <= MAX_FIELD, `url kept ${rec.urls[0].length} characters`);
  assert.ok(rec.urls.length <= MAX_URLS, `kept ${rec.urls.length} urls`);
});

// ---- password history through the round trip --------------------------------

test('password history survives export and import', () => {
  // The history is the safety net applyPatch keeps — the old password a bad
  // rotation is recovered from — and stripping it from the export cut it out
  // of the one file people restore from.
  const records = [
    newRecord(
      {
        type: LOGIN,
        title: 'Example',
        username: 'ben',
        password: 'new',
        urls: ['https://example.com'],
        history: [{ password: 'old', changed: 1_700_000_000_000 }],
      },
      1_700_000_100_000,
    ),
  ];

  const back = fromJson(toJson(records));
  assert.deepEqual(back[0].history, [{ password: 'old', changed: 1_700_000_000_000 }]);
});

test('history from a file is built entry by entry, never adopted wholesale', () => {
  const raw = JSON.stringify({
    records: [
      {
        type: 'login',
        title: 'Example',
        username: 'ben',
        password: 'new',
        history: [
          { password: 'kept', changed: 123 },
          { password: 'undated', changed: 'not-a-number' },
          { password: '', changed: 5 }, // nothing to keep
          'junk',
          { changed: 9 }, // no password at all
          { password: 'extra-keys', changed: 7, evil: { deep: true } },
        ],
      },
    ],
  });

  const [rec] = fromJson(raw);
  assert.deepEqual(rec.history, [
    { password: 'kept', changed: 123 },
    { password: 'undated', changed: 0 },
    { password: 'extra-keys', changed: 7 },
  ]);
});

test('a login with no history imports with an empty one, not a missing one', () => {
  const [rec] = fromJson(JSON.stringify([{ type: 'login', username: 'ben', password: 'x' }]));
  assert.deepEqual(rec.history, []);
});

// ---- the encrypted backup, named for what it is -----------------------------

test('an encrypted backup is refused by name, with the way through', () => {
  // On the bad day a person reaches for Import holding the backup file, and
  // "does not look like a BENCpass export" told them the file was broken. It
  // is not broken; it is sealed, and the message now says what actually reads
  // it.
  const backup = JSON.stringify({
    meta: { format: 'bencpass-vault', kdf: {} },
    envelopes: [{ id: 'x', rev: 1, n: 'n', ct: 'ct' }],
  });

  assert.throws(
    () => parse(backup),
    (err) =>
      err instanceof TransferError &&
      err.code === 'encrypted-backup' &&
      /Rescue/.test(err.message),
  );
});
