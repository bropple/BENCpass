# bencpass-server

The sync endpoint. Stores ciphertext, orders it with a sequence number, and
refuses a write from a client that has not seen the latest one. It holds no key,
so it cannot read a record, cannot merge, and cannot tell good ciphertext from
damaged — which is why it keeps snapshots.

```
go run . -dir ./data          # prints a bootstrap enrolment code
```

| flag | default | |
|---|---|---|
| `-addr` | `127.0.0.1:8788` | listen address; `:0` picks a free port |
| `-dir` | `./data` | data directory |
| `-cert` / `-key` | — | TLS; usually unnecessary, see below |
| `-snapshots` | `50` | snapshots retained |

Build all targets with `tools/build-server.sh`, which asserts each binary is
static rather than assuming it.

---

## Running it on TrueNAS SCALE (tested against 24.10 Electric Eel)

Electric Eel moved Apps from Kubernetes to Docker, so a Custom App installed
from YAML is the route. The whole job is: publish the image once, then paste one
file.

### 1. Publish the image

Push the repository to GitHub. `.github/workflows/server-image.yml` builds
`linux/amd64` and `linux/arm64` and pushes to GHCR on every tag and on `main`.

**Then make the package public, once**, at
`github.com/<you>?tab=packages`. This is the step everyone forgets, and a
private package fails on the NAS as a pull error that does not mention
permissions.

### 2. Prepare the dataset

Create a dataset for the data — **Datasets → Add Dataset** — then make it owned
by the user the container runs as. In **Edit Permissions**, set the owner to
uid/gid `568` (`apps`).

This is the step that actually goes wrong. The server creates its data directory
`0700` and writes `0600`; if the dataset belongs to anyone else, the first run
dies on a permission error against `/data` and prints nothing else.

### 3. Install

**Apps → Discover Apps → ⋮ → Install via YAML.** Name it `bencpass`, lowercase.
Paste `truenas-app.yaml` and change the two lines marked `CHANGE ME` — the
image path and the dataset path.

### 4. Check it

Open `http://<nas>:8788/` in a browser. There is a status page with P. Gon on
it, reporting the version, the sequence number and how many devices are
enrolled — which is the quickest way to confirm an enrolment actually landed.

The bootstrap enrolment code is in the app's logs: **Apps → bencpass → Logs**.
It is valid for 30 minutes and single-use.

If you set up the app through the wizard rather than YAML, point **Portal
Configuration** at port 8788 path `/` and the app card gets a working button.

There is no icon field for Custom Apps on 24.10 — the YAML screen takes a name
and a Compose file and nothing else — so P. Gon lives on the status page rather
than the app tile.

### On TrueNAS CORE

CORE is FreeBSD and has no Docker. Build `GOOS=freebsd` and run it in a jail;
Go cross-compiles there without complaint. CORE is the legacy line, so this is
not the path being maintained.

### Do not put the binary in the OS filesystem

SCALE's root filesystem is read-only and replaced wholesale on upgrade. A binary
dropped in `/usr/local/bin` disappears the next time you update, silently, and
the first you hear of it is a client that cannot sync.

The two places that survive an upgrade are a **dataset** and the **Init/Shutdown
Scripts** in the UI, which live in the config database. A pre-init script
launching a binary from a dataset is a legitimate low-tech alternative to a
container if you would rather not run one.

### The data directory must be a dataset

Not a path inside the container. Two reasons: the obvious one, and that ZFS
snapshots of that dataset are a better backstop than this server's own snapshot
rotation. A periodic snapshot task costs nothing to configure and covers
failures the application-level rotation cannot — including this server having a
bug in it.

### The gotcha that will actually bite you

**Ownership.** The container runs as uid 568 (`apps` on SCALE) and the server
creates its data directory `0700` and writes `0600`. If the dataset is owned by
anyone else, the first run fails with a permission error on `/data` and nothing
else. Either `chown` the dataset to 568 or change `user:` in `compose.yaml` to
match what owns it.

### TLS: let Tailscale do it

The `-cert`/`-key` flags exist, but on a NAS the tidier answer is not to use
them:

```
tailscale serve --bg 8788
```

That terminates TLS with a real Let's Encrypt certificate for the machine's
`*.ts.net` name and proxies to the plain-HTTP server on localhost. No cert to
obtain, renew, or make readable by a container running as another user, and the
same endpoint works on the LAN and from outside it.

Keep the container's published port on the LAN and let Tailscale reach it. Do
not forward 8788 from your router.

If you run Tailscale as a TrueNAS app rather than on the host, note that the
container gets its own tailnet identity — which changes the name clients
connect to, and is a common half-hour of confusion.

---

## Security properties, stated plainly

**What the server protects.** Every request is signed with a per-device
HMAC-SHA256 key issued at enrolment, over method, path, timestamp and a hash of
the body. That stops anyone on the network from writing to the store, forging a
device, or rewriting a request in flight, and it works over plain HTTP — which is
what makes the LAN fallback acceptable.

**What it does not.** The server stores the vault header: the KDF parameters and
the password-wrapped vault key, because a newly enrolled machine needs them to
bootstrap. So anyone who takes `store.json` can mount an **offline attack on your
master password**. This is inherent to any synced vault rather than specific to
this one, and Argon2id at 128 MiB is the whole of what stands between a stolen
file and the contents. Choose the master password accordingly, and do not put
this on the public internet.

**Enrolment.** The first device uses a bootstrap code printed to the console —
access to the machine is the authorisation. Every later device is enrolled with
a code minted by an already-enrolled one. Codes are single-use and expire after
30 minutes. Revoking a lost machine means deleting one device key, not rotating
the vault.
