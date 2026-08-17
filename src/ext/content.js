// The content script. Runs inside every page, and is the least trusted part of
// this extension — it shares a process and a DOM with whatever the page is.
//
// It is therefore kept deliberately stupid. It reports what fields exist, it
// draws an anchor, and it writes a value it is handed. Every judgement — which
// field is the username, whether this origin may receive a credential at all —
// happens in the background page, which can check the frame's real identity
// with the browser instead of asking the frame.
//
// A classic script, not a module: MV2 content scripts cannot be modules. That
// is convenient here, because it makes importing the crypto core impossible by
// construction.

(() => {
  'use strict';

  const MSG = {
    DESCRIBE: 'describe',
    CANDIDATES: 'candidates',
    CAPTURE: 'capture',
    FILL: 'fill',
    FILL_TARGET: 'fill-target',
    DISMISS: 'dismiss',
    LOCKSTATE: 'lockstate',
    NOTICE: 'notice',
  };

  const MARK = 'data-bencpass';
  const BOUND = 'data-bencpass-bound';

  // Anchors are swept and rebuilt constantly; the overlay and the page's own
  // fields must never be caught by that sweep. So the selector names the value
  // rather than the attribute — a bare [data-bencpass] also matched the overlay
  // iframe, which is why the menu deleted itself about a third of a second
  // after opening, and would have matched the page's inputs too and removed
  // them from the document.
  const ANCHOR_SEL = `[${MARK}="anchor"]`;
  const OVERLAY_ID = 'bencpass-overlay-frame';
  const TOAST_ID = 'bencpass-toast-frame';

  /** Anything this extension put in the page. */
  const isOurs = (node) =>
    Boolean(node && node.nodeType === 1 && node.closest(`[${MARK}], [${BOUND}]`));

  let fields = []; // live elements, index-aligned with the descriptors sent
  let groups = []; // per-form roles, as the background classified them
  let formIds = new WeakMap();
  let formSeq = 0; // WeakMap has no .size — see groupOf
  let locked = true;
  let activeGroup = null; // the form the open menu belongs to
  let anchorEl = null;
  let menuKind = 'login'; // which menu anchorEl was opened as
  let rescanTimer = null;

  // ---- finding fields ------------------------------------------------------

  /**
   * Collect the form controls, descending into open shadow roots.
   *
   * Selects included: country is a dropdown on nearly every checkout and state
   * on most American ones, so leaving them out meant an address could be filled
   * except for the two fields most likely to be mandatory.
   */
  function collect(root, out) {
    const nodes = root.querySelectorAll('input, textarea, select');
    for (const el of nodes) out.push(el);
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) collect(el.shadowRoot, out);
    }
    return out;
  }

  function isVisible(el) {
    if (!el.getClientRects().length) return false;
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    if (Number(style.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    if (r.width <= 8 || r.height <= 8) return false;

    // Parked off-screen — `left: -9999px` and its cousins — is the standard way
    // to hide a honeypot while keeping it technically rendered, and it defeats
    // every check above: such a field still has client rects, a real size, full
    // opacity and `display: block`. The self-test caught two anchors on exactly
    // that.
    //
    // In *document* coordinates, deliberately. Viewport coordinates made this
    // answer change as the page scrolled, and visibility feeds classification:
    // scroll a checkout far enough that its street and city boxes sit above the
    // fold and the group has fewer than two structural address fields left, so
    // the next rescan decides it was never an address form and drops every
    // anchor on it. That is exactly the "P. Gons disappear after I fill it in"
    // symptom — the form had scrolled, not changed.
    const docLeft = r.left + window.scrollX;
    const docTop = r.top + window.scrollY;
    if (docLeft + r.width <= 0 || docTop + r.height <= 0) return false;

    // The same rule for the other side. clientWidth is the layout viewport,
    // which does not move with the scroll position — so this stays a statement
    // about the page rather than about where the window is. Downward is not
    // checked at all: below the fold is where most of a long form lives.
    const layoutWidth = document.documentElement.clientWidth;
    if (layoutWidth && docLeft >= layoutWidth) return false;

    return true;
  }

  function labelFor(el) {
    if (el.labels && el.labels.length) return el.labels[0].textContent ?? '';
    const wrapper = el.closest('label');
    if (wrapper) return wrapper.textContent ?? '';
    const id = el.getAttribute('id');
    if (id) {
      const lab = document.querySelector(`label[for="${CSS.escape(id)}"]`);
      if (lab) return lab.textContent ?? '';
    }
    return '';
  }

  /**
   * Which form an input belongs to; one shared bucket for those with none.
   *
   * The counter is explicit because WeakMap has no `.size` — it cannot have
   * one, since it cannot enumerate its own keys. Reading it gave `undefined`,
   * so every form was numbered `undefined + 1` = NaN, and Map treats NaN as
   * equal to NaN, so all of them landed in one group. The result was
   * indistinguishable from the whole-document classification this replaced,
   * which is why nothing appeared to change.
   */
  function groupOf(el) {
    const form = el.form ?? el.closest('form');
    if (!form) return 0;
    if (!formIds.has(form)) formIds.set(form, ++formSeq);
    return formIds.get(form);
  }

  function describe(el, index) {
    return {
      index,
      group: groupOf(el),
      tag: el.tagName.toLowerCase(),
      // `el.type` rather than the attribute, so a <select> reports
      // `select-one` instead of defaulting to `text` and being mistaken for a
      // box something could be typed into.
      type: String(el.type ?? el.getAttribute('type') ?? 'text').toLowerCase(),
      name: el.getAttribute('name') ?? '',
      id: el.getAttribute('id') ?? '',
      autocomplete: el.getAttribute('autocomplete') ?? '',
      placeholder: el.getAttribute('placeholder') ?? '',
      ariaLabel: el.getAttribute('aria-label') ?? '',
      label: labelFor(el).trim().slice(0, 120),
      disabled: el.disabled === true,
      readOnly: el.readOnly === true,
      visible: isVisible(el),
    };
  }

  async function scan() {
    const found = collect(document, []);
    if (!found.length) {
      fields = [];
      groups = [];
      placeAnchors();
      return;
    }
    formIds = new WeakMap();
    formSeq = 0;
    const descriptors = found.slice(0, 300).map(describe);

    let reply;
    try {
      reply = await browser.runtime.sendMessage({ type: MSG.DESCRIBE, fields: descriptors });
    } catch {
      // Background asleep, or the extension reloading. Keep the last state that
      // worked rather than replacing it with nothing: committing the new field
      // list and an empty set of groups swept every anchor off the page and put
      // none back, while the click handlers already bound to the fields carried
      // on opening the menu — anchors gone, dropdown still working.
      return;
    }

    fields = found;
    groups = reply?.groups ?? [];
    locked = reply?.locked !== false;
    placeAnchors();
  }

  /** The roles for whichever form an element sits in. */
  function groupFor(el) {
    const index = fields.indexOf(el);
    if (index < 0) return null;
    return (
      groups.find(
        (g) =>
          [g.login.username, g.login.password, g.login.newPassword, g.login.otp].includes(index) ||
          (g.address ?? []).some((a) => a.index === index),
      ) ?? null
    );
  }

  const rescan = () => {
    clearTimeout(rescanTimer);
    rescanTimer = setTimeout(scan, 300);
  };

  // ---- the anchor ----------------------------------------------------------
  //
  // A small mark on the fields BENCpass can help with. Clicking it is the
  // explicit action that opens the menu. Nothing is offered, and certainly
  // nothing is filled, without one — a page that renders a hidden login form
  // and waits would otherwise harvest a credential on load.

  function placeAnchors() {
    document.querySelectorAll(ANCHOR_SEL).forEach((el) => el.remove());

    // Every form on the page, not just the first. Treating the document as one
    // form left every login below the first one unmarked.
    const targets = new Map(); // element -> which menu it opens
    for (const g of groups) {
      // A username box is anchored when there is a current password to go with
      // it, or when this is the username half of a two-step sign-in — where
      // filling the username alone is the whole point, and there is no password
      // field for anything to land in.
      //
      // What is excluded is the sign-up group: its username anchor offered the
      // stored pool, and picking an entry wrote that entry's password into the
      // "choose a password" box.
      const has = (i) => i !== null && i !== undefined;
      if (has(g.login.password) || (g.usernameOnly && has(g.login.username))) {
        for (const i of [g.login.username, g.login.password]) {
          if (i === null || i === undefined) continue;
          const el = fields[i];
          if (el) targets.set(el, 'login');
        }
      }
      // A box asking the user to choose a new password gets its own menu, which
      // offers to generate one and nothing else. Offering the existing pool
      // there invites reuse at the exact moment a fresh password is free.
      const fresh = fields[g.login.newPassword];
      if (fresh) targets.set(fresh, 'signup');
      // Address fields get an anchor too. Without one there was no way to ask
      // for an address at all — the menu existed and nothing ever opened it.
      for (const { index } of g.address ?? []) {
        const el = fields[index];
        if (el && !targets.has(el)) targets.set(el, 'address');
      }
    }
    for (const [el, kind] of targets) attachAnchor(el, kind);
  }

  const SVG_NS = 'http://www.w3.org/2000/svg';

  /**
   * P. Gon, drawn rather than loaded.
   *
   * An <img> would need the icon in web_accessible_resources, which widens what
   * a page can fingerprint the extension by. The shapes carry inline styles
   * because the wrapper's `all: initial` resets `fill`, and fill inherits.
   */
  /**
   * P. Gon, drawn rather than loaded.
   *
   * Addresses get the darker of his two canonical colours — his own edge tone
   * rather than his fill — so a login anchor and an address anchor are not the
   * same mark. Same character, quieter role, no new colour introduced.
   */
  function gonMark(isLocked, kind) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 200 200');
    svg.setAttribute('width', '18');
    svg.setAttribute('height', '18');

    const body = document.createElementNS(SVG_NS, 'path');
    body.setAttribute('d', 'M 100,16 L 179.89,74.04 L 149.37,167.96 L 50.63,167.96 L 20.11,74.04 Z');
    body.setAttribute(
      'style',
      kind === 'address'
        ? 'fill:#254d75;stroke:#3d7dbf;stroke-width:8'
        : 'fill:#3d7dbf;stroke:#254d75;stroke-width:8',
    );

    const visor = document.createElementNS(SVG_NS, 'rect');
    visor.setAttribute('x', '53.8');
    visor.setAttribute('y', '95.8');
    visor.setAttribute('width', '92.4');
    visor.setAttribute('height', '28.56');
    visor.setAttribute('style', 'fill:#9a9d94');

    const stripe = document.createElementNS(SVG_NS, 'rect');
    stripe.setAttribute('x', '70.6');
    stripe.setAttribute('y', '103.36');
    stripe.setAttribute('width', '58.8');
    stripe.setAttribute('height', '13.44');
    // The visor is the lock indicator, the same as on the gate: red locked,
    // green open.
    stripe.setAttribute('style', `fill:${isLocked ? '#d84a3a' : '#78b946'}`);

    svg.append(body, visor, stripe);
    return svg;
  }

  function attachAnchor(el, kind = 'login') {
    const dot = document.createElement('div');
    dot.setAttribute(MARK, 'anchor');
    // `all: initial` first, so the page's own stylesheet cannot restyle this
    // into something invisible or enormous.
    dot.style.cssText =
      'all: initial; position: absolute; width: 18px; height: 18px; cursor: pointer;' +
      'z-index: 2147483646; line-height: 0;';
    dot.title =
      kind === 'address'
        ? 'BENCpass — addresses'
        : kind === 'signup'
          ? 'BENCpass — generate a password'
          : 'BENCpass';
    dot.append(gonMark(locked, kind));

    dot.addEventListener('mousedown', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openMenu(el, kind);
    });

    // Clicking the field opens the menu too, the way Firefox's own login
    // autocomplete does — the anchor alone is a small target and not an obvious
    // one. Still an explicit act by the user; nothing opens or fills on its own.
    if (!el.hasAttribute(BOUND)) {
      el.setAttribute(BOUND, '1');
      el.addEventListener('click', () => {
        if (!document.getElementById(OVERLAY_ID)) openMenu(el, kind);
      });
    }

    document.body.appendChild(dot);
    position(dot, el);
  }

  function position(node, el) {
    const r = el.getBoundingClientRect();
    node.style.top = `${window.scrollY + r.top + (r.height - 18) / 2}px`;
    node.style.left = `${window.scrollX + r.right - 24}px`;
  }

  // ---- the menu ------------------------------------------------------------
  //
  // An iframe pointing at an extension page. It has to be an iframe: anything
  // rendered into the page's own DOM can be read and rewritten by the page,
  // which would hand the list of usernames to whatever is running there and let
  // it fake a click on an entry.

  async function openMenu(el, kind = 'login') {
    closeMenu();
    activeGroup = groupFor(el);
    let reply;
    try {
      // The tokens go with the request so the background can answer with those
      // and only those. A form with a postcode box and nothing else has no
      // reason to be handed a phone number, and the way to guarantee that is
      // for the phone number never to leave the vault, rather than for it to be
      // sent and then not used.
      reply = await browser.runtime.sendMessage({
        type: MSG.CANDIDATES,
        kind,
        tokens: kind === 'address' ? (activeGroup?.address ?? []).map((a) => a.token) : undefined,
      });
    } catch {
      return;
    }
    // A locked vault returns a session with a single placeholder candidate, so
    // the menu can offer to unlock. Bailing on reply.locked meant clicking a
    // field while locked did nothing at all, which is the state most in need of
    // an explanation.
    if (!reply || !reply.sessionId || !reply.candidates.length) return;

    anchorEl = el;
    menuKind = kind;
    const frame = document.createElement('iframe');
    frame.id = OVERLAY_ID;
    frame.setAttribute(MARK, 'overlay');
    // The session id does NOT go in the URL. This element lives in the page's
    // own DOM, so page script can read `frame.src` — which would hand it both
    // the extension's UUID and a live session id, and overlay.html is
    // web-accessible, so it could then run its own privileged copy against that
    // session and clickjack a fill out of it. The id is posted to the frame
    // after load instead, where the page cannot reach it: a cross-origin
    // contentWindow cannot be listened to, and the targetOrigin below means a
    // swapped document receives nothing.
    frame.src = browser.runtime.getURL('ext/overlay.html');
    // Match the field's width the way a native autocomplete panel does, with a
    // floor so a narrow box does not produce an unreadable menu.
    const box = el.getBoundingClientRect();
    frame.style.cssText =
      `all: initial; position: absolute; width: ${Math.max(240, Math.round(box.width))}px;` +
      `height: ${Math.min(260, 40 + reply.candidates.length * 46)}px;` +
      'z-index: 2147483647; border: 1px solid #1e2c3d; border-radius: 3px;' +
      'box-shadow: 0 4px 16px rgba(0,0,0,0.5); background: #0c1420; color-scheme: dark;';

    const extensionOrigin = new URL(browser.runtime.getURL('')).origin;
    frame.addEventListener(
      'load',
      () => {
        frame.contentWindow?.postMessage(
          { bencpass: 'session', sessionId: reply.sessionId },
          extensionOrigin,
        );
      },
      { once: true },
    );

    document.body.appendChild(frame);
    frame.style.top = `${window.scrollY + box.bottom + 2}px`;
    frame.style.left = `${window.scrollX + Math.max(4, box.left)}px`;

    setTimeout(() => document.addEventListener('mousedown', onOutside, true), 0);
  }

  function onOutside(e) {
    // A mousedown inside the iframe never reaches this document, so this only
    // sees clicks on the page — but the anchor and the field the menu belongs
    // to are ours, and clicking either must not dismiss it.
    if (isOurs(e.target)) return;
    closeMenu();
  }

  function closeMenu() {
    document.getElementById(OVERLAY_ID)?.remove();
    document.removeEventListener('mousedown', onOutside, true);
  }

  // ---- filling -------------------------------------------------------------

  /**
   * Set a value in a way frameworks notice.
   *
   * React tracks the previous value on the DOM node and ignores an `input`
   * event whose value it believes it already knows, so assigning `el.value`
   * directly leaves the field looking filled and the framework's state empty —
   * the form then submits nothing. Going through the prototype's own setter
   * bypasses React's override and updates its tracker.
   */
  function setValue(el, value) {
    const proto =
      el instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement
        : el instanceof HTMLSelectElement
          ? HTMLSelectElement
          : HTMLInputElement;
    const setter = Object.getOwnPropertyDescriptor(proto.prototype, 'value')?.set;
    el.focus();
    if (setter) setter.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  /**
   * Choose an option in a dropdown.
   *
   * A select cannot be assigned an arbitrary string — setting `value` to
   * something no option carries silently selects nothing at all, which is worse
   * than leaving it alone because the form then looks answered and is not. So
   * the option is found first, and the select is only touched if one matches.
   *
   * `candidates` is the value and its alternatives: `US`, `United States`,
   * `USA` all name the same country, and the page picked one of them. Each is
   * tried against the option's value and its text, exactly, then folded — which
   * is what makes `Côte d'Ivoire` match `CÔTE D’IVOIRE`.
   */
  function selectOption(el, candidates) {
    const options = [...el.options];
    // The same folding as `foldName` in core/address.js, which is where it is
    // explained and tested. It is repeated rather than imported because a
    // content script cannot be a module, and the option text only exists here.
    const fold = (s) =>
      String(s ?? '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[\u2018\u2019]/g, "'")
        .toLowerCase()
        .replace(/&/g, ' and ')
        .replace(/[^a-z0-9]+/g, ' ')
        .trim();

    for (const want of candidates) {
      if (!want) continue;
      const hit =
        options.find((o) => o.value === want || o.text.trim() === want) ??
        options.find((o) => fold(o.value) === fold(want) || fold(o.text) === fold(want));
      if (hit) {
        setValue(el, hit.value);
        return true;
      }
    }
    return false;
  }

  const at = (i) => (i === null || i === undefined ? null : fields[i] ?? null);

  function fill(kind, values, alts) {
    if (kind === 'address') return fillAddress(values, alts);

    // The form the menu was opened from, not whichever one happens to be first.
    const login = activeGroup?.login ?? groups[0]?.login ?? {};
    if (kind === 'generated') {
      const target = at(login.newPassword) ?? at(login.password);
      if (target) setValue(target, values.password);
      // And the confirmation box, or the form rejects it and the generator has
      // saved nobody anything.
      const confirm = at(login.confirmPassword);
      if (confirm && confirm !== target) setValue(confirm, values.password);
      return;
    }

    const user = at(login.username);
    // Never newPassword. A stored password belongs in a box asking for the
    // current one, never in one asking the user to choose a new one.
    const pass = at(login.password);
    if (user && values.username) setValue(user, values.username);
    if (pass && values.password) setValue(pass, values.password);
    // A username-only step has nowhere to put the password, and must not be
    // given one to hold until the next page.
    if (!pass && user) lastSubmitted.username = values.username ?? '';

    // What was put there, so that submitting it untouched can be recognised as
    // the non-event it is. Signing in with a stored password is the ordinary
    // case, and being asked to save what was just handed over is the manager
    // failing to remember its own answer of two seconds ago.
    lastFilled.username = values.username ?? '';
    lastFilled.password = values.password ?? '';
  }

  /**
   * Write an address into the form the menu was opened from.
   *
   * Every token was derived in the background, which holds the record and knows
   * how to turn it into whatever the page asked for — a full name out of two
   * name fields, one street block out of three lines, a country name out of a
   * country code. Nothing is composed here; this only puts strings where they
   * go, and picks an option when the field is a dropdown.
   */
  function fillAddress(values, alts) {
    const address = activeGroup?.address ?? groups.flatMap((g) => g.address);
    // What actually lands in the boxes, which is not always what came out of
    // the record: a phone number may lose its country code to fit, a country
    // may go in as a name. Recorded here so that submitting the form untouched
    // is recognised as such, rather than offered back as a new address.
    const written = {};

    for (const { index, token } of address) {
      const el = at(index);
      if (!el) continue;
      const value = values[token];
      if (!value) continue; // nothing stored for it, or nothing derivable

      const candidates = [value, ...(alts?.[token] ?? [])];
      if (el.tagName === 'SELECT') {
        if (selectOption(el, candidates)) written[token] = el.value;
      } else {
        const chosen = textValue(el, token, candidates, values);
        setValue(el, chosen);
        written[token] = chosen;
      }
    }
    lastFilledAddress = Object.keys(written).length ? written : null;
  }

  /**
   * Which spelling of a value to type into a plain box.
   *
   * The background offers the value and its alternatives; the choice between
   * them depends on the element, which only this side can see.
   *
   * `maxlength` is the honest signal for the phone problem. A number is stored
   * with its country code because that is what the field name `tel` means, but
   * a great many forms have a single Phone box sized for the domestic form and
   * nothing else. Rather than guess which country's conventions a page has in
   * mind, take it at its word: if the full value does not fit and a shorter
   * spelling does, the shorter one is what was being asked for.
   */
  function textValue(el, token, candidates, values) {
    // An explicit autocomplete="country" asks for the code, which is what the
    // token means. A box merely *called* country is one a person types a name
    // into, and typing "US" into it is how you get an order shipped nowhere.
    if (token === 'country' && !el.getAttribute('autocomplete') && values['country-name']) {
      return values['country-name'];
    }

    const max = Number(el.getAttribute('maxlength')) || 0;
    if (max > 0) {
      const fits = candidates.find((c) => c.length <= max);
      if (fits) return fits;
    }
    return candidates[0];
  }

  // ---- the save prompt -----------------------------------------------------
  //
  // The badge on the toolbar icon is no use to someone who is not already
  // looking for it, and the operating system's own notification never arrived
  // once — swallowed by a notification daemon, a focus setting or a permission,
  // with no way to find out which from in here. So the prompt is drawn by the
  // extension, in the corner of the page, where nothing else can suppress it.
  //
  // An iframe on the extension's origin, like the menu: the page can cover it
  // but cannot read it or click it. The notice id goes to it by postMessage
  // after load, never in the URL.

  function showToast(noticeId, kind) {
    hideToast();

    const frame = document.createElement('iframe');
    frame.id = TOAST_ID;
    frame.setAttribute(MARK, 'toast');
    frame.src = browser.runtime.getURL('ext/toast.html');
    // An address needs room for the name box; a login does not.
    const height = kind === 'address' ? 148 : 104;
    frame.style.cssText =
      `all: initial; position: fixed; right: 16px; bottom: 16px; width: 330px;` +
      `height: ${height}px; z-index: 2147483647; border: 1px solid #1e2c3d;` +
      'border-radius: 3px; box-shadow: 0 6px 22px rgba(0,0,0,0.55);' +
      'background: #0c1420; color-scheme: dark;';

    const extensionOrigin = new URL(browser.runtime.getURL('')).origin;
    frame.addEventListener(
      'load',
      () => {
        frame.contentWindow?.postMessage({ bencpass: 'notice', noticeId }, extensionOrigin);
      },
      { once: true },
    );

    document.body.appendChild(frame);
  }

  const hideToast = () => document.getElementById(TOAST_ID)?.remove();

  // The toast asks to be closed rather than closing itself, because it cannot:
  // it is framed by this document and has no reach into it.
  window.addEventListener('message', (event) => {
    const frame = document.getElementById(TOAST_ID);
    if (!frame || event.source !== frame.contentWindow) return;
    if (event.data?.bencpass === 'toast-close') hideToast();
  });

  // ---- capture -------------------------------------------------------------

  const lastSubmitted = { username: '', password: '', address: null };

  // The last thing BENCpass itself wrote into this page's fields. Kept so that
  // submitting it unchanged can be told apart from typing something new.
  const lastFilled = { username: '', password: '' };
  let lastFilledAddress = null; // token -> the string actually written

  function remember() {
    const login = activeGroup?.login ?? groups[0]?.login ?? {};
    const user = at(login.username);
    const pass = at(login.password) ?? at(login.newPassword);
    if (user?.value) lastSubmitted.username = user.value;
    if (pass?.value) lastSubmitted.password = pass.value;

    // Addresses are worth keeping too. Typed once into a checkout, they are
    // otherwise typed again at the next one.
    const address = {};
    for (const g of groups) {
      for (const { index, token } of g.address ?? []) {
        const el = at(index);
        if (el?.value?.trim()) address[token] = el.value.trim();
      }
    }
    // Two fields is the floor for calling it an address; a lone email box on a
    // newsletter form is not one.
    if (Object.keys(address).length >= 2) lastSubmitted.address = address;
  }

  function offerCapture() {
    // Signing in with a password BENCpass filled, unchanged, teaches it
    // nothing. The background declines these too, but only when it can match
    // the record — and it cannot on the second page of a two-step sign-in,
    // where the username is nowhere on screen. Here the comparison is against
    // what was actually written into the box, so it holds either way.
    const untouched =
      lastFilled.password &&
      lastSubmitted.password === lastFilled.password &&
      (!lastSubmitted.username || lastSubmitted.username === lastFilled.username);

    if (lastSubmitted.password && !untouched) {
      browser.runtime
        .sendMessage({
          type: MSG.CAPTURE,
          username: lastSubmitted.username,
          password: lastSubmitted.password,
        })
        .catch(() => {});
    }

    // The same rule for addresses: an address picked from the menu and sent
    // back untouched has nothing in it to learn. Equality both ways, so that
    // adding one field the record did not have — an apartment number, say —
    // still counts as a change worth offering to keep.
    const sameAsFilled =
      lastFilledAddress &&
      lastSubmitted.address &&
      Object.keys(lastSubmitted.address).length === Object.keys(lastFilledAddress).length &&
      Object.entries(lastFilledAddress).every(([t, v]) => lastSubmitted.address[t] === v);

    if (lastSubmitted.address && !sameAsFilled) {
      browser.runtime
        .sendMessage({ type: MSG.CAPTURE, kind: 'address', address: lastSubmitted.address })
        .catch(() => {});
    }

    lastSubmitted.username = '';
    lastSubmitted.password = '';
    lastSubmitted.address = null;
  }

  // A submit event is the clean signal and is often never fired: a great many
  // sign-in forms are a div and a click handler that calls fetch(). So the
  // values are remembered on every input, and the offer is made on whichever of
  // these happens first.
  document.addEventListener('input', remember, true);
  document.addEventListener('submit', () => { remember(); offerCapture(); }, true);
  window.addEventListener('pagehide', offerCapture, { capture: true });

  // A single-page app navigating without unloading, which is the case both of
  // the above miss.
  let lastUrl = location.href;
  setInterval(() => {
    if (location.href === lastUrl) return;
    lastUrl = location.href;
    offerCapture();
    rescan();
  }, 1000);

  // ---- messages from the background ---------------------------------------

  browser.runtime.onMessage.addListener((msg) => {
    if (msg?.type === MSG.FILL) {
      fill(msg.kind, msg.values ?? {}, msg.alts ?? {});
      closeMenu();
      return Promise.resolve({ ok: true });
    }
    if (msg?.type === MSG.FILL_TARGET) {
      // getTargetElement resolves the element the context menu was opened on,
      // which is not necessarily the focused one — right-clicking does not
      // always move focus, and guessing from document.activeElement fills the
      // wrong box on a form with several.
      const el = browser.menus?.getTargetElement?.(msg.targetElementId);
      if (el) setValue(el, msg.values?.password ?? '');
      return Promise.resolve({ ok: Boolean(el) });
    }
    if (msg?.type === MSG.NOTICE) {
      if (msg.noticeId) showToast(String(msg.noticeId), msg.kind);
      else hideToast();
      return Promise.resolve({ ok: true });
    }
    if (msg?.type === MSG.LOCKSTATE) {
      locked = Boolean(msg.locked);
      closeMenu();
      // A locked vault cannot save anything, so an offer to save is now a lie.
      if (locked) hideToast();
      placeAnchors();
      return Promise.resolve({ ok: true });
    }
    if (msg?.type === MSG.DISMISS) {
      // The field the menu was last opened against, before closeMenu forgets
      // which one that was. Falling straight to the first login field on the
      // page reopened the menu somewhere else entirely on anything with more
      // than one form — including, on a checkout, an address field.
      const previous = anchorEl;
      closeMenu();
      if (msg.open) {
        const login = groups[0]?.login ?? {};
        const target =
          previous ?? at(login.password) ?? at(login.username) ?? at(login.newPassword);
        if (target) openMenu(target, previous ? menuKind : 'login');
      }
      return Promise.resolve({ ok: true });
    }
  });

  // ---- start ---------------------------------------------------------------

  if (window.top !== window.self && !document.querySelector('input[type=password]')) {
    // Most third-party frames on a page are advertising. Scanning them all is
    // wasted work; a frame that grows a password field later is caught by the
    // observer below.
  }

  // Ignore the extension's own additions and removals. Without this, appending
  // an anchor triggers a rescan, which removes and re-adds every anchor, which
  // triggers another — a loop that also took the open menu with it each time.
  new MutationObserver((records) => {
    for (const record of records) {
      const touched = [...record.addedNodes, ...record.removedNodes];
      if (touched.length && touched.every(isOurs)) continue;
      rescan();
      return;
    }
  }).observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener('scroll', () => placeAnchors(), { passive: true });
  window.addEventListener('resize', () => placeAnchors(), { passive: true });

  scan();
})();
