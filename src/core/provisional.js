// A generated password is written down before it is filled, not after.
//
// The old arrangement offered to save it: the password went into the page, the
// site accepted it on submit, and the vault only learned it if the person then
// pressed Save on a toast that was drawn into the very page the submit
// navigated away from. Miss the toast, close the tab, or let the vault lock,
// and the site held a password that existed nowhere else. For a password
// manager that is the one failure that cannot be allowed, so the order is now
// reversed: generating IS saving, and the submit merely completes the record
// with the username it was made for.

import { LOGIN } from './model.js';
import { scoreRecord, NO_MATCH } from './match.js';

/**
 * Persist a freshly generated password as a provisional entry for `host`.
 *
 * Regenerating replaces rather than accumulates: clicking "Generate" three
 * times on one sign-up form means three passwords were shown and the last one
 * is the one in the field, so it is the one worth keeping — and only the last
 * fill can have reached the site.
 *
 * The caller persists the vault; this only writes into it.
 *
 * @returns the id of the provisional record.
 */
export async function keepGenerated(vault, { host, url, password }, now = Date.now()) {
  const open = vault
    .list(LOGIN)
    .find((r) => r.provisional && (host ? scoreRecord(r, host) > NO_MATCH : !(r.urls ?? []).length));
  if (open) {
    await vault.update(open.id, { password }, now);
    return open.id;
  }
  return vault.add(
    {
      type: LOGIN,
      // Titled after the site like an ordinary capture; a page with no host —
      // a file:// form, say — still gets its password kept, under a name that
      // says what it is rather than pretending to know where it belongs.
      title: host || 'Generated password',
      username: '',
      password,
      urls: url ? [url] : [],
      provisional: true,
    },
    now,
  );
}

/**
 * The sign-up went through: attach the username and drop the provisional mark.
 *
 * Called when a capture arrives whose password matches the provisional entry —
 * the person just submitted the generated password, so the record is complete
 * and there is nothing left to ask them. The caller persists the vault.
 */
export async function completeGenerated(vault, record, username, now = Date.now()) {
  await vault.update(
    record.id,
    { username: username || record.username || '', provisional: false },
    now,
  );
  return record.id;
}
