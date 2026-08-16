// Behaviour for the awkward cases on the form-shapes page. Not part of the
// extension — this is the thing being tested against.

// Section 6: an input that fights a naive fill, the way a framework-controlled
// one does. React keeps its own record of the value on the node and reverts
// anything it did not set itself; assigning `.value` directly is silently undone.
// Going through the prototype's own setter is what makes a fill stick, so this
// reproduces the failure without pulling in React.
for (const id of ['f1', 'f2']) {
  const el = document.getElementById(id);
  let framework = '';
  const native = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');

  Object.defineProperty(el, 'value', {
    get: () => framework,
    set(v) {
      // A direct assignment is ignored, exactly as a controlled input ignores one.
      framework = framework;
      native.set.call(el, framework);
    },
    configurable: true,
  });

  // Only a real input event, which is what the native setter path produces,
  // moves the framework's own state along.
  el.addEventListener('input', () => {
    framework = native.get.call(el);
  });
}

// Section 7: a login form that appears long after load.
document.getElementById('late').addEventListener('click', () => {
  const slot = document.getElementById('late-slot');
  if (slot.querySelector('form')) return;

  const form = document.createElement('form');
  form.innerHTML = `
    <label for="h1">Username</label>
    <input id="h1" name="username" autocomplete="username">
    <label for="h2">Password</label>
    <input id="h2" name="password" type="password" autocomplete="current-password">
    <button>Sign in</button>`;
  slot.append(form);
});

// Nothing here submits anywhere. Capture is exercised by the submit event, and
// a real navigation would just lose the page.
document.addEventListener('submit', (e) => {
  e.preventDefault();
  const note = document.createElement('p');
  note.className = 'expect';
  note.textContent = 'Submitted — BENCpass should now offer to save (badge on the toolbar icon).';
  e.target.append(note);
});
