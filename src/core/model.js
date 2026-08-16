// The shape of a record's plaintext, and the rules for changing it.
//
// Everything here lives inside the ciphertext, so the server learns none of it —
// not the timestamps, not the type of a record, not how many there are of each.
//
// Two record types share one vault. That costs the layers underneath nothing:
// crypto.js seals opaque bytes and merge.js works on envelopes, so neither has
// any opinion about what is inside. Only this file and the UI care.

export const LOGIN = 'login';
export const ADDRESS = 'address';
export const TYPES = [LOGIN, ADDRESS];

export const HISTORY_MAX = 20;

// How far ahead of the local clock a timestamp may claim to be before it is
// treated as wrong rather than merely fast. Machines drift, NTP has not always
// run, and an imported record dated 2049 sorts to the top of every list forever.
export const SKEW_TOLERANCE_MS = 5 * 60 * 1000;

const COMMON = { title: '', notes: '' };

export const EMPTY_LOGIN = Object.freeze({
  ...COMMON,
  urls: [],
  username: '',
  password: '',
  totp: '', // otpauth:// URI
  fields: [], // [{ name, value, hidden }]
});

/**
 * Address fields are named with the WHATWG autofill tokens verbatim, hyphens
 * and all, rather than translated into camelCase.
 *
 * It is uglier to type here and it is the right trade: the fill code reads a
 * token off the page's `autocomplete` attribute and looks it up directly, with
 * no mapping table in between. A mapping table is a second place for the field
 * set to drift, and drift there shows up as a form that silently half-fills.
 *
 * Deliberately one flat type rather than a separate "identity" record: shipping
 * forms ask for the name, the phone and the address together, and splitting
 * them would mean filling one form from two records.
 */
export const EMPTY_ADDRESS = Object.freeze({
  ...COMMON,
  'name': '',
  'organization': '',
  'address-line1': '',
  'address-line2': '',
  'address-level2': '', // city / town / suburb
  'address-level1': '', // state / province / region — absent in much of Europe
  'postal-code': '',
  'country': '', // ISO 3166-1 alpha-2, because the `country` token wants a code
  'tel': '',
  'email': '',
});

export const emptyFor = (type) => (type === ADDRESS ? EMPTY_ADDRESS : EMPTY_LOGIN);

/** Fields a query is matched against, per type. */
export function searchableFields(record) {
  if (record.type === ADDRESS) {
    return [
      record.title,
      record['name'],
      record['organization'],
      record['address-line1'],
      record['address-line2'],
      record['address-level2'],
      record['address-level1'],
      record['postal-code'],
      record['email'],
      record.notes,
    ];
  }
  return [record.title, record.username, record.notes, ...(record.urls ?? [])];
}

/**
 * A one-line summary for a list row.
 *
 * NOT a locale-aware address formatter, and not trying to be one — those differ
 * by country in ways a join cannot capture (Japan reverses the order, much of
 * Europe has no state line). This is a label for a picker, and the stored fields
 * remain the authority for anything being filled.
 */
export function summarise(record) {
  if (record.type === ADDRESS) {
    return [record['address-line1'], record['address-level2'], record['postal-code']]
      .filter(Boolean)
      .join(', ');
  }
  return record.username || record.urls?.[0] || '';
}

/**
 * Clamp a timestamp that claims to be in the future.
 *
 * Returns the clamped value and, when it differed, the original — so the UI can
 * still show what the source file said without letting it distort sorting or
 * an age audit.
 */
export function clampTime(t, now, tolerance = SKEW_TOLERANCE_MS) {
  if (!Number.isFinite(t) || t <= 0) return { t: now, claimed: null };
  if (t > now + tolerance) return { t: now, claimed: t };
  return { t, claimed: null };
}

export function newRecord(fields = {}, now = Date.now()) {
  const type = fields.type ?? LOGIN;
  if (!TYPES.includes(type)) throw new Error(`unknown record type: ${type}`);

  const rec = {
    ...emptyFor(type),
    ...fields,
    type,
    created: now,
    updated: now,
    lastUsed: 0,
    timesUsed: 0,
  };

  if (type === LOGIN) {
    // Set even when the password starts empty: an entry that later gains one
    // should not read as "changed at the dawn of time".
    rec.passwordChanged = now;
    rec.history = [];
  }
  return rec;
}

/**
 * Apply a patch, maintaining the timestamps and — for logins — the password
 * history.
 *
 * `updated` and `passwordChanged` are kept distinct on purpose. Only the second
 * can answer "how old is this password", which is the entire point of an age
 * audit — and renaming an entry or adding a note must not reset it.
 */
export function applyPatch(plain, patch, now = Date.now()) {
  const next = { ...plain, ...patch, type: plain.type };
  next.updated = now;

  // An address has no password and therefore no history and no age. Guarding on
  // the type rather than on the field being present keeps a stray `password`
  // key in a patch from quietly growing one.
  if (plain.type !== LOGIN) return next;

  const changed =
    patch.password !== undefined && patch.password !== plain.password;

  if (changed) {
    next.passwordChanged = now;
    // The old password is kept because a bad merge, a mistyped rotation or a
    // site that silently rejected the change are all recoverable from it and
    // from nothing else. This is the cheapest safety net in the design.
    if (plain.password) {
      next.history = [
        { password: plain.password, changed: plain.passwordChanged },
        ...(plain.history ?? []),
      ].slice(0, HISTORY_MAX);
    }
  } else {
    next.history = plain.history ?? [];
  }

  return next;
}

/** Record a fill. Kept separate from applyPatch: using an entry is not editing it. */
export function markUsed(plain, now = Date.now()) {
  return { ...plain, lastUsed: now, timesUsed: (plain.timesUsed ?? 0) + 1 };
}

/**
 * Normalise anything arriving from an importer or an older format.
 *
 * Importers are the main source of missing and nonsensical timestamps —
 * Firefox's CSV export carries timeCreated, timeLastUsed and timePasswordChanged
 * but not timesUsed, and other managers carry fewer still.
 */
export function normalise(input, now = Date.now()) {
  const type = TYPES.includes(input.type) ? input.type : LOGIN;

  const created = clampTime(input.created ?? now, now);
  const updated = clampTime(input.updated ?? created.t, now);
  const lastUsed = input.lastUsed ? clampTime(input.lastUsed, now) : { t: 0 };

  const rec = {
    ...emptyFor(type),
    ...input,
    type,
    created: created.t,
    updated: updated.t,
    lastUsed: lastUsed.t,
    timesUsed: Number.isFinite(input.timesUsed) ? input.timesUsed : 0,
  };

  let pwClaimed = null;
  if (type === LOGIN) {
    const pwChanged = clampTime(input.passwordChanged ?? created.t, now);
    rec.passwordChanged = pwChanged.t;
    rec.history = Array.isArray(input.history) ? input.history.slice(0, HISTORY_MAX) : [];
    rec.urls = Array.isArray(input.urls) ? input.urls : [];
    rec.fields = Array.isArray(input.fields) ? input.fields : [];
    pwClaimed = pwChanged.claimed;
  }

  const claimed = created.claimed ?? updated.claimed ?? pwClaimed;
  if (claimed) rec.claimedTime = claimed;

  return rec;
}
