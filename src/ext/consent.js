// Consent for what sync sends, as a decision that can be tested.
//
// The manifest declares `authenticationInfo` and `personallyIdentifyingInfo`
// as *optional* data collection, which is accurate: nothing leaves the machine
// until a server is configured. But optional data-collection permissions are
// real permissions in Firefox's model — off until granted, listed in
// about:addons under Permissions and Data, and revocable there. Declaring them
// and never asking would mean about:addons showing both switched off while the
// vault syncs, so the ask happens where the decision is made: at the moment
// somebody puts a server address in the box.
//
// The caller must run this inside the event handler: `permissions.request`
// needs a user gesture, and awaiting anything first spends it.

/**
 * Will the person grant this, or have they already?
 *
 * `request` goes first and `contains` is the fallback, and that order is the
 * whole of this function. It was the other way round for one release, for a
 * good reason — a machine with every toggle on in about:addons could not join,
 * because request() failed for reasons of its own and the failure read as a
 * refusal — and consulting `contains` first fixed that case by breaking the
 * commoner one. Awaiting any async extension API ends the user-input handler,
 * so the question spent the gesture that the answer needed:
 *
 *   permissions.request may only be called from a user input handler
 *
 * on every machine where the permission was NOT already held, which is every
 * fresh install. The first machine never saw it, because it had granted the
 * permission months earlier and never reached the request at all.
 *
 * Asking first costs nothing: request() on a permission already held resolves
 * true without drawing a prompt. And when it throws — a spent gesture, or
 * whatever broke it on that first machine — `contains` is exactly the right
 * question to ask afterwards, because by then there is no gesture left to
 * spend. Both failures are covered, and neither can cause the other.
 *
 * The verdict says which of the two "no"s happened, because they send a person
 * to different places: `refused` is the person declining the prompt, and the
 * fix is to grant it; `error` is the prompt itself failing, and pointing at
 * about:addons — where everything may well already be on — is pointing at the
 * one place that cannot help.
 *
 * @returns {{ ok: boolean, reason?: 'refused' | 'error', message?: string }}
 */
export async function syncConsent(api, wanted) {
  // Outside the extension (the preview harness, a plain file) there is no
  // permissions API and nothing will be transmitted by anything this gates.
  if (!api?.request || !wanted?.length) return { ok: true };

  try {
    // Nothing is awaited above this line, and nothing may be: the caller's
    // gesture has to still be alive when this call is made.
    const granted = await api.request({ data_collection: wanted });
    return granted ? { ok: true } : { ok: false, reason: 'refused' };
  } catch (err) {
    // Now — and only now, with the gesture already spent either way — ask
    // whether it was held all along. This is the machine whose toggles are on
    // and whose request() broke anyway.
    try {
      if (await api.contains?.({ data_collection: wanted })) return { ok: true };
    } catch {
      // contains() failing tells us nothing, so it decides nothing; fall
      // through to the error below, which is what actually happened.
    }

    // A rejection that survives the check above is a real failure, not a
    // formality. This used to return true, on the reasoning that a browser too
    // old to know `data_collection` would throw rather than answer. No such
    // browser can install this: strict_min_version is 142 and the key shipped
    // in 139. Swallowing it saved the address with no consent recorded at all,
    // which is precisely the state this function exists to prevent.
    console.warn('BENCpass: the data-collection prompt failed', err);
    return { ok: false, reason: 'error', message: String(err?.message ?? err) };
  }
}
