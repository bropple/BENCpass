// Static server for the design preview, plus one endpoint that exists solely to
// make screenshots deterministic.
//
// `firefox --screenshot` captures on the load event, and the manager is not on
// screen at that point: unlocking runs Argon2, which is 400 ms of deliberate
// work. The screenshot therefore catches the gate every time.
//
// /__hold?ms=N answers a script request after N ms. A deferred script delays
// load until it arrives, so injecting one into the preview page moves the
// capture to after the app has settled. Nothing about the app changes to
// accommodate the camera.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const root = process.argv[2] ?? process.cwd();
const port = Number(process.argv[3] ?? 8731);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
};

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/__hold') {
    const ms = Math.min(Number(url.searchParams.get('ms') ?? 1000), 30_000);
    await new Promise((r) => setTimeout(r, ms));
    res.writeHead(200, { 'content-type': 'text/javascript' }).end('/* held */');
    return;
  }

  // normalize collapses any ../ before it is joined, so the server cannot be
  // walked out of the repo. It only ever serves this tree.
  const path = join(root, normalize(url.pathname));
  if (!path.startsWith(root)) {
    res.writeHead(403).end('no');
    return;
  }

  try {
    const body = await readFile(path);
    res.writeHead(200, { 'content-type': TYPES[extname(path)] ?? 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404).end('not found');
  }
}).listen(port, '127.0.0.1', () => {
  console.log(`serving ${root} on http://127.0.0.1:${port}`);
});
