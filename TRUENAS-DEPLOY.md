# Running the sync server on TrueNAS

The server stores ciphertext and holds no key. It cannot read a record, which is
why it is safe to run it on a NAS and reach it from anywhere.

Everything here was checked against the real binary rather than remembered. The
first-run output is quoted verbatim.

---

## Before you start: make the image pullable

The container image is at `ghcr.io/bropple/bencpass-server`. It is published by
CI on every push that touches `server/**`.

**The package is private until you change it, and TrueNAS will fail with a
generic pull error that never mentions permissions.** That is the single most
likely way to lose half an hour here.

The repository does *not* have to be public for this. Package visibility on GHCR
is set separately:

> github.com/users/bropple/packages/container/bencpass-server/settings →
> Danger Zone → Change visibility → Public

If you would rather keep it private, give TrueNAS a registry credential instead:
a fine-grained token with `read:packages`, added under **Apps → Settings →
Manage Container Images → Add credential**.

### A note on tags

There are no git tags in this repository yet, so the only tags that exist are
`latest` and `main` — and `latest` moves with every push to main. If you want a
deployment that does not change under you, tag a release first:

```sh
git tag v0.11.0 && git push --tags
```

which makes CI publish `ghcr.io/bropple/bencpass-server:0.11.0` and
`:v0.11.0`. Pin to that rather than `latest`.

---

## The dataset

Create one for the server's data — for example `tank/apps/bencpass`.

The container runs as **UID 568, GID 568** (TrueNAS `apps`), and the server
creates its directory `0700` and its files `0600`. If the dataset is owned by
anyone else the container exits immediately with:

```
cannot open store: mkdir /data/snapshots: permission denied
```

and TrueNAS shows an app that will not start, with the reason only in the logs.
(`mkdir /data` rather than `/data/snapshots` means something else: the mount
itself is not there.)

So:

```sh
chown -R 568:568 /mnt/tank/apps/bencpass
```

**Snapshot this dataset.** It holds the wrapped vault key, every record, and
every device key. Losing it does not merely lose the server — see *If you lose
the data directory* at the bottom, which is worse than you would expect.

---

## Installing

**Apps → Discover Apps → Install via YAML**, with:

```yaml
services:
  bencpass:
    image: ghcr.io/bropple/bencpass-server:latest   # or a version tag
    container_name: bencpass
    restart: unless-stopped
    user: "568:568"
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    ports:
      - "8788:8788"
    volumes:
      - /mnt/tank/apps/bencpass:/data
```

The image is built `FROM scratch` and holds one static binary. There is no
shell in it, so there is nothing to exec into — the logs are the whole
diagnostic surface.

The entrypoint already passes `-addr 0.0.0.0:8788 -dir /data`; you do not need
to supply them.

### The flags, if you want them

| flag | default | what it does |
|---|---|---|
| `-addr` | `127.0.0.1:8788` | listen address. The container overrides this to `0.0.0.0:8788` |
| `-dir` | `./data` | data directory. The container overrides this to `/data` |
| `-cert` / `-key` | none | TLS. Both or neither — see *TLS* below, you probably want neither |
| `-snapshots` | `50` | how many store snapshots to keep. `0` disables |

There are no environment variables and no config file.

---

## First run

The log will say exactly this:

```
no devices enrolled yet
bootstrap enrolment code (valid 30 minutes): hscrLJLXLDXG
listening on http://0.0.0.0:8788 (no TLS; payload is E2E encrypted and requests are signed)
```

That code is what your first machine needs. It is single-use and expires in
thirty minutes.

**If it expires before you get to it, just restart the app.** As long as no
device has enrolled, every start mints and prints a fresh one. You do not need
to wipe anything.

Once at least one device is enrolled, restarts print only the `listening on`
line — no code. That is not a fault; codes are minted from inside the extension
after that.

Check it is up by visiting `http://10.0.0.20:8788` in a browser: a small status
page shows the version, the sequence number and how many devices are enrolled.

---

## Machine one: create the vault

1. Open BENCpass → **Manage** (or the sidebar).
2. Create a vault with your master password. This is the one that matters and it
   is not recoverable.
3. Gear icon → **Sync**:
   - **Server**: `http://10.0.0.20:8788` — your NAS's LAN address.
   - Press **Test**. It should say *Answered. 0 changes stored.*
   - **Enrolment code**: paste `hscrLJLXLDXG` — the code from the log.
4. Firefox will ask permission to send your passwords and addresses to that
   server. Refusing it means the address is not saved.
5. Press **Sync**. This is the step that puts the vault header on the server,
   and nothing else can join until it has happened once.

## Machines two and three: join it

On machine one, gear → **Sync** → mint a code for the next machine.

Then on the new machine, at the BENCpass gate, choose
**"Already have a vault on a server? Join it"** and give it:

- the server address,
- the code,
- **the same master password**.

It pulls the vault header down and opens it with that password, which yields the
*same* vault key as machine one. That is the whole difference between joining and
creating: a new vault would have its own key and could never read a record the
first machine wrote.

---

## Reaching it from outside: Tailscale

Do not forward 8788 on your router. Install Tailscale on the NAS and run:

```sh
tailscale serve --bg 8788
```

That terminates HTTPS on 443 with a real Let's Encrypt certificate for the
machine's `*.ts.net` name and proxies to the server. It needs MagicDNS and
HTTPS certificates enabled once in the tailnet admin console.

Then in the extension, gear → **Sync** → **Also reachable at**:

```
https://bencpass.your-tailnet.ts.net
```

That is the *same* server by another route. The extension tries the LAN address
first and falls back to this only when the first cannot be reached at all.

**Use the `https://` name, not the Tailscale IP.** Plain http is accepted only
to addresses the extension can identify as private — `10.x`, `192.168.x`,
`172.16–31.x`, loopback, `.local`. Tailscale's own range, `100.64.0.0/10`, is
shared with ISP carrier-grade NAT, and from inside a browser there is no way to
tell the two apart — so `http://100.x.x.x:8788` is refused. With https there is
nothing to tell apart: the certificate proves the name.

**No other reverse proxy.** Every request is signed over the `Host` header it
was sent with, so anything that rewrites Host — nginx and Caddy do by default —
makes every request fail with `401`, which looks exactly like a bad credential.
`tailscale serve` is safe because it passes Host through unchanged.

### TLS directly, if you insist

`-cert` and `-key` exist. You then have to obtain a certificate, renew it, and
make it readable by a container running as 568 with no shell. `tailscale serve`
avoids all three.

---

## What will bite you, in order

**1. The image will not pull.** Package is private. See the top of this file.
The error does not say "permissions".

**2. The app will not start.** Dataset not owned by 568:568. The log says
`cannot open store: mkdir /data/snapshots: permission denied`.

**3. The address is refused in Settings.** `http://truenas:8788` (a bare
hostname) and `http://100.x.x.x:8788` (a Tailscale IP) are both rejected. Use
the LAN IP, `truenas.local`, or the https Tailscale name.

**4. Everything returns 401 and it looks like a bad key.** Three different
causes, and the error cannot tell them apart:
   - a proxy rewriting `Host` (see above);
   - the NAS clock being wrong — more than 5 minutes slow or 30 seconds fast
     will fail every request. A NAS without NTP after a power cut does this.
   - a genuinely wrong device key.

   The **Test** button distinguishes the first two from the third only partly:
   it uses an unsigned endpoint, so it will happily say *Answered* while signed
   requests fail. If Test succeeds and Sync says 401, suspect the clock.

**5. A protocol mismatch after an upgrade.** If the server and extension
disagree about the signed format, **Test** says so explicitly — *"That server
speaks protocol 3 and this BENCpass speaks 2"* — rather than leaving you with a
401. Update whichever is behind.

**6. `latest` moved under you.** Tag a release and pin to it.

---

## If you lose the data directory

Worse than it sounds, and worth knowing before it happens.

Wiping `/data` while machines are still enrolled strands them twice. Their
device keys are gone, so every request returns 401 — and re-enrolling does not
fix it, because each client remembers the highest sequence number it has seen
and refuses a server that reports a lower one:

```
server reports sequence 0, lower than the 1 already seen — refusing a rollback
```

That guard is correct: it is what stops a rolled-back or impostor server
resurrecting deleted records. But there is no reset button in the extension
today, so recovery means clearing the extension's storage on each machine — in
practice a fresh profile — and joining again.

Your vault survives all of this: it lives in each browser, and any machine can
publish its header to a fresh server. But it is an afternoon you did not need.

**Snapshot the dataset.** ZFS snapshots are the whole answer here.

---

## Revoking a device

Gear → **Sync** → **Machines**. Every enrolled machine is listed, with the one
you are using marked, and each can be renamed or revoked.

Rename them. The name is whatever the machine called itself when it enrolled —
`mac`, `windows`, `linux` — and two machines with the same name are two rows
you cannot tell apart at the moment you are trying to decide which one was
stolen.

Revoking takes effect immediately: that key stops authenticating anything, and
the machine cannot come back without a new code.

The last device cannot be revoked, and the server will refuse. A store with no
devices cannot be reached at all — nothing could enrol, because minting a code
needs a device to sign the request, and nothing could read, because every route
is signed. The only way back would be deleting the data directory, which takes
the vault header with it.
