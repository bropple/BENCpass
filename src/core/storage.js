// Storage adapters.
//
// The vault serialises to a plain object of ciphertext; where that lands is a
// separate decision. Two implementations exist so the core can be tested with
// no browser present, and so a future desktop or CLI client needs no changes
// here beyond a third adapter.
//
// Everything written through these is already encrypted. `browser.storage.local`
// is an unencrypted IndexedDB inside the Firefox profile directory, readable by
// anyone with the profile — which is fine, and only fine because nothing
// readable goes into it.

const KEY = 'bencpass.vault';

export class MemoryStorage {
  #data = new Map();

  async read(key = KEY) {
    return this.#data.get(key) ?? null;
  }

  async write(value, key = KEY) {
    // Structured-clone on the way in, so a caller mutating its own object after
    // writing cannot retroactively change what was "persisted". The real
    // adapters get this for free; the test double should not be more forgiving
    // than production.
    this.#data.set(key, structuredClone(value));
  }

  async clear(key = KEY) {
    this.#data.delete(key);
  }
}

/**
 * localStorage, for opening the UI as a plain file during development.
 *
 * Not for shipping: it is synchronous, size-limited, and shared per origin. It
 * is listed here rather than improvised in the UI so that the one place storage
 * is chosen stays this file.
 */
export class LocalStorageStorage {
  async read(key = KEY) {
    const raw = globalThis.localStorage?.getItem(key);
    return raw ? JSON.parse(raw) : null;
  }

  async write(value, key = KEY) {
    globalThis.localStorage.setItem(key, JSON.stringify(value));
  }

  async clear(key = KEY) {
    globalThis.localStorage.removeItem(key);
  }
}

/** Whatever this environment actually has. The extension always gets the first. */
export function pickStorage() {
  if (globalThis.browser?.storage?.local) return new WebExtStorage();
  if (globalThis.localStorage) return new LocalStorageStorage();
  return new MemoryStorage();
}

/**
 * browser.storage.local.
 *
 * Note that this is not atomic: a write interrupted by a crash can leave a
 * partial value. The sync engine's answer is that the server holds snapshots
 * and the envelopes are individually authenticated, so a torn local write is
 * recoverable rather than fatal — but it is a real gap and is written down here
 * rather than discovered later.
 */
export class WebExtStorage {
  constructor(area = globalThis.browser?.storage?.local) {
    if (!area) throw new Error('browser.storage.local is unavailable');
    this.area = area;
  }

  async read(key = KEY) {
    const got = await this.area.get(key);
    return got?.[key] ?? null;
  }

  async write(value, key = KEY) {
    await this.area.set({ [key]: value });
  }

  async clear(key = KEY) {
    await this.area.remove(key);
  }
}
