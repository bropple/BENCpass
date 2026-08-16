// The single place Argon2 is imported.
//
// Vendored as one ES module rather than resolved from node_modules, because the
// extension can do neither a bare specifier nor an import map — the latter needs
// an inline <script type="importmap">, which the extension CSP forbids. Node and
// Firefox both resolve this path identically, so the tests exercise exactly what
// ships.
//
// Regenerate with tools/vendor.sh. The extension's manifest still needs
// 'wasm-unsafe-eval' in its CSP, or the module compiles nothing and the vault
// does not open.

export { argon2id } from '../vendor/argon2.js';
