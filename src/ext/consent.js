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
 * Is the permission held, and if not, will the person grant it?
 *
 * `contains` is consulted before anything is requested. It did not use to be,
 * and the miss was a machine that could not join at all: the permission was
 * already granted — every toggle on in about:addons — but request() failed
 * anyway (it can, for reasons that have nothing to do with consent), and the
 * failure was reported as "joining needs permission" to a person looking at
 * the permission, granted, on their own screen. Already held means already
 * answered; nothing needs a gesture and nothing can fail.
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
    if (await api.contains?.({ data_collection: wanted })) return { ok: true };
  } catch {
    // contains() failing must not become a denial — the request below is
    // still a perfectly good way to find out, and it is the authority anyway.
  }

  try {
    const granted = await api.request({ data_collection: wanted });
    return granted ? { ok: true } : { ok: false, reason: 'refused' };
  } catch (err) {
    // A rejection is a refusal, not a formality.
    //
    // This used to return true, on the reasoning that a browser too old to know
    // `data_collection` would throw rather than answer. No such browser can
    // install this: strict_min_version is 142 and the key shipped in 139. So the
    // only rejections reachable here are real ones — a spent user gesture above
    // all — and swallowing them saved the address with no consent recorded at
    // all, which is precisely the state this function exists to prevent.
    console.warn('BENCpass: the data-collection prompt failed', err);
    return { ok: false, reason: 'error', message: String(err?.message ?? err) };
  }
}
