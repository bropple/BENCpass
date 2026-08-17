// Working out what the inputs on a page are for.
//
// Pure: it takes plain descriptors and returns roles, so the whole thing is
// testable under Node without a DOM. The traversal that builds descriptors from
// real elements lives in the content script and is deliberately thin, because
// anything with judgement in it belongs here where it can be tested.
//
// Order of trust:
//   1. the autocomplete attribute, when the page bothers to set one
//   2. name / id / label / placeholder heuristics
//   3. position relative to the password field
//
// Sites that get autocomplete right are the easy half. The rest is why this
// file is the largest part of the extension.

export const USERNAME = 'username';
export const PASSWORD = 'password';
export const NEW_PASSWORD = 'new-password';
export const OTP = 'otp';

/** Address roles are the WHATWG tokens verbatim, matching the record's keys. */
export const ADDRESS_TOKENS = new Set([
  'name',
  'given-name',
  'family-name',
  'organization',
  'street-address',
  'address-line1',
  'address-line2',
  'address-level1',
  'address-level2',
  'postal-code',
  'country',
  'country-name',
  'tel',
  'email',
]);

// Tokens that may precede the field name in an autocomplete attribute:
// "shipping address-line1", "section-foo billing tel", "home email".
const MODIFIERS = new Set(['shipping', 'billing', 'home', 'work', 'mobile', 'fax', 'pager']);

/**
 * Pull the meaningful token out of an autocomplete attribute.
 *
 * Returns null for "off" and "on", which say nothing about what a field is —
 * "off" in particular is a request not to autofill, not a description, and is
 * routinely set on fields this extension still needs to identify.
 */
export function autocompleteToken(value) {
  if (!value) return null;
  const parts = String(value).toLowerCase().trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return null;

  const last = parts[parts.length - 1];
  if (last === 'off' || last === 'on') return null;
  if (last.startsWith('section-') || MODIFIERS.has(last)) return null;
  return last;
}

/** True when the attribute carries a shipping or billing section marker. */
export function autocompleteSection(value) {
  const parts = String(value ?? '').toLowerCase().split(/\s+/);
  if (parts.includes('shipping')) return 'shipping';
  if (parts.includes('billing')) return 'billing';
  return null;
}

/** Everything a heuristic may look at, lowercased and run together. */
function haystack(f) {
  return [f.name, f.id, f.placeholder, f.ariaLabel, f.label, f.dataAttrs]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

// No trailing word boundary: Microsoft's field is literally called `loginfmt`,
// and requiring a non-letter after the keyword misses it and its many cousins.
// The cost is a looser match, which is acceptable because this is only ever a
// fallback after position, and NOT_A_CREDENTIAL screens the obvious traps.
const USERNAME_HINTS = /(^|[^a-z])(user|usr|uid|login|logon|email|e-mail|account|identifier|signin)/;
const NEW_HINTS = /(new|confirm|retype|repeat|verify|again|second)/;
const OTP_HINTS = /(otp|one-?time|2fa|mfa|totp|auth(entication)?-?code|verification-?code|security-?code)/;

// Fields that look like credentials to a keyword search but are not. A search
// box called "q" or a site search labelled "Search users" would otherwise be
// filled with an email address on every page load.
const NOT_A_CREDENTIAL = /(search|query|coupon|promo|discount|voucher|captcha|zip|postal)/;

export function isFillableInput(f) {
  if (f.tag !== 'input' && f.tag !== 'textarea') return false;
  if (f.disabled || f.readOnly) return false;
  const t = (f.type ?? 'text').toLowerCase();
  return ['text', 'email', 'tel', 'password', 'url', 'number', 'search', 'textarea', ''].includes(t);
}

export const isPasswordInput = (f) => (f.type ?? '').toLowerCase() === 'password';

/**
 * Classify the credential fields of one form (or of a form-less group).
 *
 * `fields` must be in DOM order — the username heuristic depends on it.
 */
export function classifyLoginFields(fields) {
  const visible = fields.filter((f) => f.visible !== false && isFillableInput(f));
  const passwords = visible.filter(isPasswordInput);

  const result = { username: null, password: null, newPassword: null, otp: null };
  if (!visible.length) return result;

  // --- passwords ---------------------------------------------------------
  //
  // Several signals mean "this is a password being set rather than entered":
  // an explicit autocomplete, a name that says so, or simply more than one
  // password box in the group — a sign-up or change-password form.
  const explicitNew = passwords.filter((f) => autocompleteToken(f.autocomplete) === 'new-password');
  const explicitCurrent = passwords.filter(
    (f) => autocompleteToken(f.autocomplete) === 'current-password',
  );

  if (explicitCurrent.length) {
    result.password = explicitCurrent[0];
    if (explicitNew.length) result.newPassword = explicitNew[0];
  } else if (explicitNew.length) {
    result.newPassword = explicitNew[0];
  } else if (passwords.length === 1) {
    const f = passwords[0];
    if (NEW_HINTS.test(haystack(f))) result.newPassword = f;
    else result.password = f;
  } else if (passwords.length > 1) {
    // Two or more boxes and nothing telling us which is which. The first is the
    // one to fill; the rest are confirmations. Treating this as a sign-up is the
    // safe reading — offering to *generate* is harmless, whereas filling an
    // existing password into a "choose a new password" box is not.
    result.newPassword = passwords[0];
  }

  // --- one-time codes ----------------------------------------------------
  result.otp =
    visible.find((f) => {
      const token = autocompleteToken(f.autocomplete);
      return token === 'one-time-code' || (!isPasswordInput(f) && OTP_HINTS.test(haystack(f)));
    }) ?? null;

  // --- username ----------------------------------------------------------
  const byAutocomplete = visible.find((f) => {
    const token = autocompleteToken(f.autocomplete);
    return token === 'username' || token === 'email';
  });

  if (byAutocomplete) {
    result.username = byAutocomplete;
  } else {
    const anchor = result.password ?? result.newPassword;
    const candidates = visible.filter(
      (f) =>
        !isPasswordInput(f) &&
        f !== result.otp &&
        !NOT_A_CREDENTIAL.test(haystack(f)) &&
        ['text', 'email', 'tel', ''].includes((f.type ?? 'text').toLowerCase()),
    );

    // The field immediately before the password is the username far more often
    // than any keyword match is, so position wins when there is a password to
    // anchor to.
    const before = anchor ? candidates.filter((f) => f.index < anchor.index) : [];
    result.username =
      before[before.length - 1] ?? candidates.find((f) => USERNAME_HINTS.test(haystack(f))) ?? null;
  }

  return result;
}

/**
 * Classify each form on the page separately.
 *
 * Fields carry a `group` — their owning <form>, or a synthetic bucket for
 * inputs with no form. Without this the whole document is treated as one form,
 * and a page with more than one login-shaped thing on it gets exactly one set
 * of roles: the classifier sees every password box at once, reads the count as
 * a sign-up, and picks the first. Every other form on the page then goes
 * unrecognised — which is not an exotic case, a login form beside a newsletter
 * box is enough.
 */
export function classifyGroups(fields) {
  const groups = new Map();
  for (const f of fields) {
    const key = f.group ?? 0;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(f);
  }

  return [...groups.entries()].map(([group, members]) => ({
    group,
    login: classifyLoginFields(members),
    address: classifyAddressFields(members),
    usernameOnly: isUsernameOnlyStep(members),
  }));
}

/**
 * Is this a page asking for a username with no password yet?
 *
 * The two-step login, which is now the common shape. Getting it wrong means
 * doing nothing on the first page of every Microsoft or Google sign-in.
 */
export function isUsernameOnlyStep(fields) {
  const visible = fields.filter((f) => f.visible !== false && isFillableInput(f));
  if (visible.some(isPasswordInput)) return false;
  return visible.some((f) => {
    const token = autocompleteToken(f.autocomplete);
    if (token === 'username' || token === 'email') return true;
    const h = haystack(f);
    if (NOT_A_CREDENTIAL.test(h)) return false;
    // An <input type="email"> on a page with no password is a username step on
    // its own, whatever it happens to be called.
    return (f.type ?? '').toLowerCase() === 'email' || USERNAME_HINTS.test(h);
  });
}

/**
 * Map address fields to record keys.
 *
 * `street-address` is a single box some sites use in place of address-line1/2,
 * and `country-name` wants the name where `country` wants the code — both are
 * normalised by the caller, which is the only place that knows the record.
 */
export function classifyAddressFields(fields) {
  const visible = fields.filter((f) => f.visible !== false && isFillableInput(f));
  const out = [];

  for (const f of visible) {
    const token = autocompleteToken(f.autocomplete);
    if (token && ADDRESS_TOKENS.has(token)) {
      out.push({ field: f, token, section: autocompleteSection(f.autocomplete) });
      continue;
    }

    const h = haystack(f);
    const guess = guessAddressToken(h, f);
    if (guess) out.push({ field: f, token: guess, section: null });
  }

  return out;
}

// Only used when the page sets no autocomplete attribute at all. Ordered most
// specific first: "address-line2" contains "address", and a postcode field is
// very often called "zip".
const ADDRESS_HINTS = [
  ['address-line2', /(address.?2|addr.?2|line.?2|apt|apartment|suite|unit)/],
  ['address-line1', /(address.?1|addr.?1|line.?1|street|^address$|shipping.?address)/],
  ['address-level2', /(city|town|suburb|locality)/],
  ['address-level1', /(state|province|region|county)/],
  ['postal-code', /(zip|postal|postcode|post.?code)/],
  ['country', /(country)/],
  ['organization', /(company|organi[sz]ation|business)/],
  ['family-name', /(last.?name|surname|family.?name)/],
  ['given-name', /(first.?name|given.?name|forename)/],
  ['name', /(full.?name|^name$|your.?name|recipient)/],
  ['tel', /(phone|tel|mobile|contact.?number)/],
  ['email', /(email|e-mail)/],
];

function guessAddressToken(h, f) {
  if (!h) return null;
  if (NOT_A_CREDENTIAL.test(h) && !/zip|postal/.test(h)) return null;
  if ((f.type ?? '').toLowerCase() === 'email') return 'email';
  if ((f.type ?? '').toLowerCase() === 'tel') return 'tel';

  for (const [token, re] of ADDRESS_HINTS) {
    if (re.test(h)) return token;
  }
  return null;
}
