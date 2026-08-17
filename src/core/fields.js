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

import { ADDRESS_TOKENS, STRUCTURAL_TOKENS } from './address.js';

export const USERNAME = 'username';
export const PASSWORD = 'password';
export const NEW_PASSWORD = 'new-password';
export const OTP = 'otp';

// Which WHATWG tokens count as part of an address, and which of those are
// strong enough evidence that a form *is* one, both live in address.js beside
// the record they describe. Re-exported because this module is where the rest
// of the extension asks about fields.
export { ADDRESS_TOKENS };

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

/**
 * A dropdown. Country is one on almost every checkout, and state on most
 * American ones, so an address that cannot answer a <select> cannot answer a
 * checkout.
 *
 * Kept separate from `isFillableInput` on purpose: a select is a candidate for
 * an address token and never for a credential. There is no such thing as a
 * password dropdown, and letting one into the login classifier would only give
 * it a new way to pick the wrong element.
 */
export const isSelect = (f) => f.tag === 'select' && !f.disabled;

/** Anything an address may be written into. */
export const isAddressControl = (f) => isSelect(f) || isFillableInput(f);

export const isPasswordInput = (f) => (f.type ?? '').toLowerCase() === 'password';

/**
 * Classify the credential fields of one form (or of a form-less group).
 *
 * `fields` must be in DOM order — the username heuristic depends on it.
 */
export function classifyLoginFields(fields) {
  const visible = fields.filter((f) => f.visible !== false && isFillableInput(f));
  const passwords = visible.filter(isPasswordInput);

  const result = {
    username: null,
    password: null,
    newPassword: null,
    confirmPassword: null,
    otp: null,
  };
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

  // The confirmation box. A generated password has to go in both, or the form
  // rejects it and the person has to paste it in by hand — at which point the
  // generator has saved them nothing.
  if (result.newPassword) {
    const after = passwords.slice(passwords.indexOf(result.newPassword) + 1);
    result.confirmPassword =
      after.find((f) => autocompleteToken(f.autocomplete) === 'new-password') ??
      after.find((f) => NEW_HINTS.test(haystack(f))) ??
      after[0] ??
      null;
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

  return [...groups.entries()].map(([group, members]) => {
    const login = classifyLoginFields(members);
    const addressFields = classifyAddressFields(members);

    // Street, city, region, postcode, country, company. Not email, phone or a
    // name — those appear on sign-in pages and newsletter boxes as readily as
    // on a checkout, and settle nothing. STRUCTURAL_TOKENS is the list.
    const structural = new Set(
      addressFields.filter((a) => STRUCTURAL_TOKENS.has(a.token)).map((a) => a.token),
    ).size;
    const looksLikeAddress = structural >= 2;

    // `isUsernameOnlyStep` alone is far too eager: any form with an email box
    // and no password satisfies it, which includes essentially every checkout.
    // Two structural address fields outrank it.
    const usernameOnly = !looksLikeAddress && isUsernameOnlyStep(members);

    // A group holding a password box, or one that is the username half of a
    // two-step sign-in, is a credential form. Its email field is a username,
    // not a contact detail for a delivery — which is what put an address anchor
    // on the sign-up and two-step forms.
    const isCredentialForm =
      !looksLikeAddress && (members.some(isPasswordInput) || usernameOnly);

    return {
      group,
      login,
      address: isCredentialForm ? [] : addressFields,
      usernameOnly,
    };
  });
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
  const visible = fields.filter((f) => f.visible !== false && isAddressControl(f));
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
// specific first, and the order carries real weight: "address-line2" contains
// "address", "tel-extension" contains neither "tel" nor "extension" reliably,
// and a postcode field is very often called "zip".
const ADDRESS_HINTS = [
  // Telephone parts before `tel`, which would otherwise swallow all of them.
  ['tel-extension', /(extension|\bext\b|ext.?no|phone.?ext)/],
  ['tel-country-code', /(country.?code|dial.?code|phone.?prefix|tel.?cc)/],
  ['tel-area-code', /(area.?code|npa)/],
  ['tel-local-prefix', /(exchange|phone.?prefix.?3)/],
  ['tel-local-suffix', /(line.?number|phone.?suffix)/],
  ['tel-national', /(national.?number|phone.?national)/],
  // Street lines, most specific number first.
  ['address-line3', /(address.?3|addr.?3|line.?3)/],
  ['address-line2', /(address.?2|addr.?2|line.?2|apt|apartment|suite|unit|floor|building)/],
  ['address-line1', /(address.?1|addr.?1|line.?1|street|^address$|shipping.?address|house)/],
  ['street-address', /(street.?address|full.?address|address.?block)/],
  // Administrative levels, finest first so "district" does not fall to "city".
  ['address-level4', /(sublocality|sub.?locality|village|hamlet)/],
  ['address-level3', /(district|neighbou?rhood|barrio|bairro|ward|dependent.?locality)/],
  ['address-level2', /(city|town|suburb|locality|municipality)/],
  ['address-level1', /(state|province|region|county|prefecture|territory|oblast)/],
  ['postal-code', /(zip|postal|postcode|post.?code|pin.?code|cep)/],
  ['country-name', /(country.?name)/],
  ['country', /(country|nation)/],
  ['organization-title', /(job.?title|position|role|occupation)/],
  ['organization', /(company|organi[sz]ation|business|employer)/],
  // Name parts. "name" last, because every one of the others contains it.
  ['honorific-prefix', /(honorific.?prefix|salutation|^title$|prefix.?name)/],
  ['honorific-suffix', /(honorific.?suffix|name.?suffix)/],
  ['additional-name', /(middle.?name|middle.?initial|additional.?name)/],
  ['family-name', /(last.?name|surname|family.?name|lname|^ln$)/],
  ['given-name', /(first.?name|given.?name|forename|fname|^fn$)/],
  ['name', /(full.?name|^name$|your.?name|recipient|contact.?name)/],
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
