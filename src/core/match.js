// Deciding whether a stored credential belongs to the page in front of you.
//
// This is the phishing boundary. Everything else in the extension can be
// merely wrong; this being wrong types your password into someone else's form.
//
// The two obvious shortcuts are both dangerous:
//
//   host.endsWith('google.com')   also matches evil-google.com
//   the last two labels           makes foo.co.uk and bar.co.uk the same site
//
// So the Public Suffix List is carried and consulted. Nothing here reaches the
// network — a password manager that asks a third party where it is safe to type
// a password has the wrong shape.

import { PSL_RULES } from '../vendor/psl.js';

/** Normalise a hostname for comparison. Does not resolve punycode. */
export function normaliseHost(host) {
  return String(host ?? '')
    .trim()
    .toLowerCase()
    .replace(/\.$/, ''); // a trailing dot is the same host
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/** An IP literal is not a domain and has no registrable part. */
export function isIpHost(host) {
  const h = normaliseHost(host);
  return IPV4.test(h) || h.includes(':') || (h.startsWith('[') && h.endsWith(']'));
}

/**
 * Hosts whose traffic does not cross the public internet.
 *
 * These are exempt from the plain-HTTP refusal. The realistic alternative is
 * refusing to fill a router, a NAS or a printer — none of which will ever have
 * a publicly trusted certificate — which trains someone to switch the warning
 * off permanently, and that is worse than the risk being avoided.
 *
 * Loopback is genuinely safe. RFC1918 and link-local are "does not leave your
 * network", which is weaker, and is the line drawn deliberately rather than by
 * accident.
 */
export function isPrivateHost(host) {
  const h = normaliseHost(host);
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (h === '::1' || h === '[::1]') return true;
  if (!IPV4.test(h)) return false;

  const [a, b] = h.split('.').map(Number);
  return (
    a === 127 || // loopback
    a === 10 || // RFC1918
    (a === 172 && b >= 16 && b <= 31) || // RFC1918
    (a === 192 && b === 168) || // RFC1918
    (a === 169 && b === 254) // link-local
  );
}

/**
 * The public suffix of a hostname, per the PSL algorithm.
 *
 * Exception rules (`!`) win over everything; otherwise the longest matching
 * rule prevails; if nothing matches, the implicit `*` rule applies and the
 * suffix is the final label.
 */
export function publicSuffix(host) {
  const h = normaliseHost(host);
  if (!h || isIpHost(h)) return h;

  const labels = h.split('.');

  // Exceptions first: `!city.kawasaki.jp` means city.kawasaki.jp is itself
  // registrable, so the suffix is one label shorter than the rule.
  for (let i = 0; i < labels.length; i++) {
    if (PSL_RULES.has('!' + labels.slice(i).join('.'))) {
      return labels.slice(i + 1).join('.');
    }
  }

  let best = '';
  for (let i = labels.length - 1; i >= 0; i--) {
    const candidate = labels.slice(i).join('.');
    const wildcard = ['*', ...labels.slice(i + 1)].join('.');
    if (PSL_RULES.has(candidate) || (i < labels.length - 1 && PSL_RULES.has(wildcard))) {
      best = candidate;
    }
  }

  // No rule at all — the implicit `*` rule. Also covers `localhost` and other
  // single-label hosts, where the whole name is the suffix and there is no
  // registrable domain below it.
  return best || labels[labels.length - 1];
}

/**
 * The registrable domain — eTLD+1. This is the unit of "same site".
 *
 * Returns null when the host *is* a public suffix (`co.uk`), because nothing
 * can be registered at that level and no credential should match it.
 */
export function registrableDomain(host) {
  const h = normaliseHost(host);
  if (!h) return null;
  if (isIpHost(h)) return h; // an IP is its own identity

  const suffix = publicSuffix(h);
  if (h === suffix) return null;

  const rest = h.slice(0, -(suffix.length + 1)).split('.');
  return `${rest[rest.length - 1]}.${suffix}`;
}

/** Whether two hosts belong to the same registrable site. */
export function sameSite(a, b) {
  const da = registrableDomain(a);
  const db = registrableDomain(b);
  if (da === null || db === null) return normaliseHost(a) === normaliseHost(b);
  return da === db;
}

export function hostOf(url) {
  try {
    return normaliseHost(new URL(url).hostname);
  } catch {
    // Bare hostnames are common in imported data, which never carries a scheme.
    const bare = normaliseHost(url).split('/')[0];
    return bare.includes('.') || bare === 'localhost' ? bare : '';
  }
}

/**
 * Does every address on this entry belong to one site?
 *
 * An entry matches on any of its addresses, which is right — one account can
 * live on two domains. But it means an entry naming both the site in front of
 * you and somewhere else is a candidate here, and anything that writes a
 * secret into such an entry writes it somewhere it will be offered again
 * elsewhere. Capture uses this to decide what it may overwrite in place.
 *
 * An entry with no addresses counts as belonging: it has never claimed to be
 * anywhere.
 */
export function belongsOnlyTo(record, host) {
  return (record?.urls ?? []).every((u) => {
    const h = hostOf(u);
    return !h || sameSite(h, host);
  });
}

/**
 * Which stored login a captured password belongs to, and whether it may be
 * written into it.
 *
 * Two answers rather than one, because the questions differ. `candidate` is
 * the entry this host and username already have, and is what decides whether
 * there is anything new to learn. `overwritable` is the entry that may be
 * *changed in place*, which is narrower: an entry naming somewhere other than
 * this site would carry the new password there too.
 *
 * Kept here rather than in the background page so it can be tested. The
 * background page cannot be imported by a test — it reaches for `browser` at
 * load — and this is the decision the whole capture path turns on.
 */
export function captureTarget(records, host, username) {
  const forHost = matchesFor(records, host);
  const candidate = forHost.find((r) => (r.username ?? '') === username) ?? null;
  return {
    forHost,
    candidate,
    overwritable: candidate && belongsOnlyTo(candidate, host) ? candidate : null,
  };
}

export const EXACT = 3;
export const SUBDOMAIN = 2;
export const SITE = 1;
export const NO_MATCH = 0;

/**
 * How well one stored URL matches a page host.
 *
 * There is deliberately no global "equivalent domains" table of the kind other
 * managers ship (amazon.com ≈ amazon.co.uk, and so on). Every entry in such a
 * table is a hand-written assertion that two different sites may receive each
 * other's passwords, and one wrong row is a phishing hole that no user ever
 * sees. A record can simply carry several URLs instead, which covers the same
 * ground under the owner's control rather than ours.
 */
export function scoreUrl(storedUrl, pageHost) {
  const stored = hostOf(storedUrl);
  const page = normaliseHost(pageHost);
  if (!stored || !page) return NO_MATCH;
  if (stored === page) return EXACT;
  if (!sameSite(stored, page)) return NO_MATCH;
  // Same registrable site. login.example.com against example.com is the common
  // and legitimate case.
  return page.endsWith('.' + stored) || stored.endsWith('.' + page) ? SUBDOMAIN : SITE;
}

/** The best score any of a record's URLs achieves against a host. */
export function scoreRecord(record, pageHost) {
  let best = NO_MATCH;
  for (const url of record.urls ?? []) {
    const s = scoreUrl(url, pageHost);
    if (s > best) best = s;
  }
  return best;
}

/**
 * Records that may be offered for a page, best match first.
 *
 * Only logins, and only ones that actually match. A record with no URL is never
 * offered automatically — it can still be filled by picking it by hand from the
 * popup, which is an explicit act naming a specific entry.
 */
export function matchesFor(records, pageHost) {
  return records
    .filter((r) => (r.type ?? 'login') === 'login')
    .map((r) => ({ record: r, score: scoreRecord(r, pageHost) }))
    .filter((m) => m.score > NO_MATCH)
    .sort(
      (a, b) =>
        b.score - a.score ||
        (b.record.timesUsed ?? 0) - (a.record.timesUsed ?? 0) ||
        (a.record.title ?? '').localeCompare(b.record.title ?? ''),
    )
    .map((m) => m.record);
}

/**
 * The gate on actually filling.
 *
 * `frameHost` is the host of the frame the field lives in, which is not always
 * the host in the address bar. A login form inside a third-party iframe is
 * either a legitimate identity provider or an injected credential harvester,
 * and from inside the page they look identical — so the credential must match
 * the frame that will receive it, not the page around it.
 *
 * Returns a reason rather than a bare false, so the UI can say why instead of
 * appearing not to work.
 */
export function canFill(record, frameHost, { pageHost = frameHost, allowInsecure = false, frameProtocol = 'https:' } = {}) {
  if ((record.type ?? 'login') !== 'login') return { ok: false, reason: 'not-a-login' };

  if (scoreRecord(record, frameHost) === NO_MATCH) {
    return { ok: false, reason: 'origin-mismatch' };
  }

  // A password typed into an http:// form crosses the network in the clear.
  if (frameProtocol === 'http:' && !allowInsecure && !isPrivateHost(frameHost)) {
    return { ok: false, reason: 'insecure-page' };
  }

  if (!sameSite(frameHost, pageHost)) {
    return { ok: false, reason: 'cross-origin-frame' };
  }

  return { ok: true };
}

/**
 * The gate on filling an address.
 *
 * An address is not origin-bound the way a credential is — any of them may
 * legitimately be typed into any checkout, so there is no host to match against.
 * The other two checks still apply and are not optional: a shipping address is
 * PII, and handing it to a third-party frame or sending it over plain HTTP is
 * the same mistake as doing it with a password, only quieter.
 */
export function canFillAddress(
  frameHost,
  { pageHost = frameHost, allowInsecure = false, frameProtocol = 'https:' } = {},
) {
  if (frameProtocol === 'http:' && !allowInsecure && !isPrivateHost(frameHost)) {
    return { ok: false, reason: 'insecure-page' };
  }
  if (!sameSite(frameHost, pageHost)) {
    return { ok: false, reason: 'cross-origin-frame' };
  }
  return { ok: true };
}

/** Addresses are not origin-bound; any of them may be offered on any form. */
export function addressesFor(records) {
  return records
    .filter((r) => r.type === 'address')
    .sort((a, b) => (a.title ?? '').localeCompare(b.title ?? ''));
}
