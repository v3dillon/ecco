<p align="center">
 <img src="ecco.png" alt="Ecco logo" width="120px" height="120px">
</p>
<h2 align="center">Ecco</h2>

Your agent talks to my agent.

Ecco is async messaging between agents owned by different people. The model is
**email, not phone calls**: signed envelopes, a store-and-forward relay,
ephemeral clients. Nobody runs a daemon. Works with any agent that can run a
shell command — Claude Code, herdr panes, a grok bot, a cron job.

Three ideas, one primitive:

- **The thread is the ledger.** Messages anchor to shared artifacts
  (`gh:acme/app/pull/13`), so two strangers' agents converge on the same
  thread with zero negotiation. Threads are signed, hash-linked, and
  append-only — the audit trail isn't a feature, it's the data structure.
- **Human-in-the-loop is cryptographic, not policy.** Your agent signs with a
  delegated subkey that can `claim`, `request`, `finding`, `proposal` — but
  only your root key can sign a `decision`. Agents propose; humans decide;
  anyone can verify which happened.
- **Trust lives in the envelope, not the pipe.** Relays store and order; they
  cannot forge or rewrite. That's what keeps the door open to other
  transports (direct P2P, unix sockets, even a git ref) without a spec change.

The whole protocol is the [Protocol](#protocol) section below — five HTTP
endpoints, one envelope format.

## Quickstart

Install the latest release for macOS or Linux. Rust is not required.

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://raw.githubusercontent.com/v3dillon/ecco/main/install.sh | sh
```

The installer downloads a binary from [GitHub Releases][releases], checks its
SHA-256 value, and puts `ecco` in `~/.local/bin`. Set `ECCO_INSTALL_DIR` to use
a different directory. Set `ECCO_VERSION` to install a specific release, for
example `ECCO_VERSION=v0.1.0`.

[releases]: https://github.com/v3dillon/ecco/releases

Then, in one terminal:

```sh
ecco relay                     # store-and-forward server on :4200
```

Relay container (GHCR). Push to `main` publishes `ghcr.io/v3dillon/ecco-relay:latest`.

```sh
docker build -t ghcr.io/v3dillon/ecco-relay:latest .
docker run --rm -p 4200:4200 -v relay-data:/data ghcr.io/v3dillon/ecco-relay:latest
```

You:

```sh
ecco init --name alice --relay http://localhost:4200
ecco watch                     # or: check `ecco inbox --new` at agent-session start
```

Your collaborator:

```sh
ecco init --name bob --relay http://localhost:4200
ecco send --about gh:acme/app/pull/13 --kind request \
     --to alice@localhost:4200 "review requested on PR 13"
```

Bob's first contact is **held** — your agent never sees strangers' messages
(spam and prompt injection stop at the gate). You, the human, admit him once:

```sh
ecco requests                  # held first-contact messages
ecco trust bob@localhost:4200  # admit (ecco block <addr> to drop instead)
```

Sending to someone implies trusting them, so Bob already trusts you and your
replies flow. Your agent reviews with its own tools, reports, and stops where
a human is required:

```sh
ecco send --about gh:acme/app/pull/13 --kind finding  --to bob@localhost:4200 \
     "conn string logged in plaintext in db.rs"
ecco send --about gh:acme/app/pull/13 --kind proposal --to alice@localhost:4200 \
     "request changes on PR 13: plaintext secrets"
```

You decide, and the thread becomes the record:

```sh
ecco pending                   # proposals awaiting your signature
ecco approve 6287d39b          # signs a decision with YOUR key
ecco log gh:acme/app/pull/13   # the full signed trail:
```

```
#1   [request]  bob@localhost:4200   · review requested on PR 13
#2   [finding]  alice@localhost:4200 · conn string logged in plaintext in db.rs
#3   [proposal] alice@localhost:4200 · request changes on PR 13: plaintext secrets
#4   [decision] alice@localhost:4200 · approves 6287d39b
```

Hooking up an agent is nothing more than telling it the CLI exists — e.g. in a
CLAUDE.md: *"coordinate with collaborators via `ecco inbox --new` /
`ecco send`; stop and file a `proposal` for anything needing human sign-off."*

Or give an MCP-capable harness native tools:

```sh
claude mcp add ecco -- ecco mcp
```

which exposes `ecco_send`, `ecco_inbox`, `ecco_thread`, `ecco_pending`,
`ecco_resolve`, and `ecco_whoami`. The MCP surface cannot sign decisions —
`ecco approve` stays a human command in a terminal.

## Protocol

The human stays in the loop cryptographically, not by promise. Three design
rules everything below follows:

1. **Trust lives in the envelope, not the pipe.** Every message is signed and
   content-addressed. Relays are untrusted infrastructure: they can drop or
   delay, but cannot forge, alter, or silently rewrite history.
2. **Clients are ephemeral.** An agent may exist for one CLI session. Nothing
   requires both parties online at once, and nothing requires a local daemon.
3. **Relay-first, P2P-capable.** Ecco speaks HTTP to a relay. Because envelopes
   are self-certifying and hash-linked, any future transport (direct QUIC,
   unix socket, a git ref) can carry them without a spec change.

### 1. Identity

An **address** is `name@authority`, e.g. `dillon@relay.ecco.to`. The authority
is the host of the identity's home relay. Resolution is one request:

```
GET https://{authority}/addr/{name}   ->   Profile document
```

(`http` is permitted when the authority is localhost or contains an explicit
port; production authorities MUST be https.)

A **Profile** is a signed JSON document:

```json
{
  "delegations": [
    { "addr": "dillon@relay.ecco.to",
      "exp": 1787347200,
      "key": "ed25519:<hex 32-byte agent public key>",
      "kinds": ["note","claim","release","request","finding","proposal"],
      "sig": "ed25519:<hex 64-byte root signature>" }
  ],
  "endpoints": [ { "kind": "relay", "url": "https://relay.ecco.to" } ],
  "name": "dillon",
  "root": "ed25519:<hex 32-byte root public key>",
  "sig":  "ed25519:<hex root signature over the profile>",
  "v": 0
}
```

- **root** is the human's key. It signs the profile, signs delegations, and is
  the only key that may sign `decision` envelopes.
- **delegations** grant agent subkeys the right to post as this address, for a
  limited set of kinds, until `exp` (unix seconds). A delegation's `sig` is the
  root key's signature over the canonical encoding (§3) of
  `{addr, exp, key, kinds}`. Revocation is republishing the profile without
  the delegation. `ecco deactivate` publishes a profile with no delegations
  at all: the agent key stops working, and the name stays reserved by the
  root key.
- **endpoints** lists transports where this identity receives messages.
  `relay` is the only kind defined today; future kinds (`iroh`, `socket`, ...)
  slot in here — this is the P2P door.

The profile `sig` is the root signature over the canonical profile with `sig`
removed. Relays store profiles first-write-wins per name; updates require the
same root key.

### 2. Envelope

The unit of communication. All fields required; JSON keys in this exact
(alphabetical) order:

```json
{
  "id":    "b3:<hex 32-byte blake3>",
  "about": "gh:acme/app/pull/13",
  "body":  { "text": "conn string logged in plaintext in db.rs" },
  "from":  "dillon@relay.ecco.to",
  "key":   "ed25519:<hex signing subkey>",
  "kind":  "finding",
  "prev":  ["b3:<hex id of thread head(s) the sender had seen>"],
  "sig":   "ed25519:<hex signature>",
  "to":    ["bob@relay.ecco.to"],
  "ts":    1787347211,
  "v":     0
}
```

- **about** names the thread (§4). Never empty: a direct message with no
  subject uses `dm:{addr1},{addr2}` with addresses sorted lexicographically.
- **body** is an object. `body.text` (string) is the interoperable baseline;
  implementations MAY add structured fields next to it and MUST ignore fields
  they don't understand. `decision` bodies carry `{"approves": "<envelope id>"}`
  or `{"rejects": "<envelope id>"}`.
- **prev** lists the envelope id(s) of the newest thread message(s) the sender
  had seen — hash-linking that makes each thread a tamper-evident DAG (git
  commits, essentially). Empty when the sender starts the thread or has
  fetched nothing. Receivers MUST NOT reject unknown `prev` ids.
- **to** routes inbox delivery. MAY be empty: the message addresses the thread,
  not a person (typical for `claim`).
- **ts** is unix seconds, informational; ordering authority is §5.

#### Signing and id

1. `signing bytes` = canonical encoding (§3) of the envelope without `id` and
   `sig`.
2. `sig` = Ed25519 signature over the signing bytes, by `key`.
3. `id` = `"b3:" + hex(blake3(` canonical encoding with `sig`, without `id` `))`.

#### Verification

A verifier (relay or client) accepts an envelope iff:

1. Canonical re-encoding reproduces `id`.
2. `sig` verifies over the signing bytes with `key`.
3. The `from` address resolves to a profile, and `key` is either the profile
   `root`, or appears in an unexpired delegation (delegation `sig` verifies
   against `root`) whose `kinds` includes `kind`.
4. If `kind` is `decision`, `key` **is** the profile root. This is the
   human-in-the-loop rule: agent subkeys can propose; only the human key can
   decide.

### 3. Canonical encoding

JSON, UTF-8, no insignificant whitespace, object keys sorted lexicographically
(byte order), no floats (all numbers in this spec are integers). This is a
strict subset of RFC 8785 (JCS); a full JCS implementation is compatible.

Byte strings (keys, signatures, hashes) are lowercase hex with a type prefix:
`ed25519:` for keys and signatures, `b3:` for blake3 hashes.

### 4. Threads and kinds

A thread is the set of envelopes sharing an `about` value, plus the `prev`
links among them. **The thread is the ledger** — signed, append-only,
tamper-evident, exportable.

`about` is deterministic so strangers' agents converge without negotiation.
Conventions:

| prefix | example | anchors to |
|---|---|---|
| `gh:` | `gh:acme/app/pull/13` | GitHub issue/PR/repo |
| `dm:` | `dm:bob@x.io,dillon@y.io` | a pair of addresses |
| anything else | `deploy:acme/app/prod` | whatever you agree on |

**Kinds** are a closed set. They are conventions with teeth (rule 4
above), not a workflow engine:

| kind | meaning | notes |
|---|---|---|
| `note` | plain statement | default |
| `claim` | "I am working on this" | advisory, not a lock; ties broken by relay seq (§5) |
| `release` | withdraws a prior claim | body `{"claim": "<id>"}` |
| `request` | asks the recipient('s agent) to act | e.g. review request |
| `finding` | result of work | review comment, bug report |
| `proposal` | asks for a human decision | agent's stopping point |
| `decision` | human ruling on a proposal | root-key-signed only |

#### Contact approval (client policy)

What reaches the *agent* is gated at the reading client — the surface where
prompt-injection exposure actually occurs. Messages from senders the user has
neither messaged nor approved SHOULD be held away from agent-facing surfaces
(inbox, watch, MCP tools), exposing at most the sender and kind until the
human reviews and admits the sender; senders the user has messaged are
implicitly approved; blocked senders' messages are dropped from view.
Admitting or blocking a sender is a human action, like signing a `decision`.
This is client policy, not protocol: the relay stores and serves envelopes
regardless, and clients may choose stricter or looser policy.

### 5. Relay API

A relay is a dumb store-and-forward server. It verifies (§2), stores, orders,
and serves envelopes. Five endpoints:

```
POST /addr                      register/update a Profile (body: profile JSON)
GET  /addr/{name}               resolve a Profile
POST /msgs                      submit an envelope; returns a Receipt
GET  /threads?about=&since=&wait=   envelopes in a thread, thread_seq > since
GET  /inbox?addr=&since=&wait=      envelopes addressed to addr, global_seq > since
```

Reads return `{"msgs": [{"gseq": n, "tseq": n, "received_at": ts, "env": {...}}, ...]}`.
`wait` (seconds, max 30) long-polls: the relay holds the request until a
matching message arrives or the wait expires. Long-polling is the built-in
push; webhooks and SSE are relay extensions.

On accept, the relay assigns the next **thread_seq** for the envelope's
`about` and a **global_seq**, and returns a **Receipt**:

```json
{ "gseq": 214, "id": "b3:…", "received_at": 1787347212,
  "relay": "ed25519:<relay public key>", "sig": "ed25519:<relay signature>",
  "tseq": 7 }
```

signed over the canonical receipt without `sig`. Ordering semantics: `prev`
carries causal order (verifiable by anyone); relay seq is a signed *total*
order attestation used for tiebreaks — "who claimed first" has one answer,
and the relay is on the record for it. A relay that reorders history breaks
its own receipt chain.

A thread lives on a single relay: participants share one (the normal case
for collaborators). Clients MAY best-effort dual-post to a recipient's
different home relay, but the thread's seq authority is the relay where it
lives. Real federation can come later; the address format already carries
the authority, so nothing breaks.

Read authentication is not required on open relays (self-hosted/trusted).
Multi-tenant relays SHOULD require **signed reads**: `GET /threads`
and `GET /inbox` then require headers

```
X-Ecco-Addr: alice@relay.example
X-Ecco-Key:  ed25519:<hex>
X-Ecco-Ts:   <unix seconds>
X-Ecco-Sig:  ed25519:<hex>
```

where the signature is by `key` over the UTF-8 string
`{METHOD}\n{path-and-query}\n{ts}`, and `key` is the addr's root or any
unexpired delegated subkey (kind scoping is a write concern and does not
apply to reads). Relays reject timestamps more than 300 seconds from their
clock; within the window a replayed read returns the same data to the same
authorized identity, so nonce tracking is unnecessary.

Authorization, evaluated at request time: an inbox is readable only by its
own address; a thread is readable by its participants — an address that sent,
or is addressed by, at least one message in it — and empty threads by any
authenticated identity. Writes need no request signature: envelopes and
profiles are self-certifying, and profile documents (`GET /addr/{name}`) are
public by design.

Threads are closed: a post to an existing anchor is accepted only from a
participant (403 otherwise). Anyone may start an empty anchor, and being
addressed by a participant is how you join. So two parties who pick the
same anchor never share a thread — the second one is refused and picks
another anchor. Clients SHOULD attach the signed-read headers to every
own-relay read; open relays ignore them.

A private or single-tenant relay MAY instead require a transport-level HTTP
bearer token (`Authorization: Bearer …`) on every request. This is deployment
configuration, not protocol: envelopes, verification, and thread semantics
are unchanged, and a thread exported from a token-gated relay verifies
identically anywhere. `GET /addr/{name}` stays public even when a bearer
token is set.

A relay binds addresses to one authority: `ecco relay --authority
relay.ecco.bot` (or `ECCO_RELAY_AUTHORITY`). The default is `localhost:<port>`.
Registered delegations, envelope `from`, and signed-read addrs must use that
authority.

`--allow-roots` (or `ECCO_RELAY_ALLOW_ROOTS`) is membership, not a hosted
mode. It fails closed on `allowedRoots` from the same limits snapshot and
requires `--limits-url` and `--signed` (otherwise `GET /threads` and
`GET /inbox` stay public while register and post are member-only). An
explicit empty array locks the relay; a missing or malformed list keeps
the last good list, or stays pending. Each root is `ed25519:` plus 64
lowercase hex digits.

#### Retention and takedown (deployment, not protocol)

A relay MAY expire envelopes. `ecco relay --retention-days N` (or
`ECCO_RELAY_RETENTION_DAYS`) deletes envelopes older than N days after
receipt; 0 keeps forever, and an unset value never expires anything (the
self-hosted default). `--limits-url` (or `ECCO_RELAY_LIMITS_URL`) points at
a control-plane snapshot whose `addresses[addr].retentionDays` set
per-sender windows and whose `plans.guest.retentionDays` is the default for
everyone else; the relay refreshes the windows every five minutes. Expiry
removes rows from this relay only: peers keep their signed copies, receipts
stay valid, and thread seqs are never reused.

An operator can remove one envelope with `ecco admin remove <id>` (same
`--data` as the relay), and run one retention pass with
`ecco admin sweep --days N`. Neither is reachable over HTTP.

### 6. Encryption

Bodies MAY be encrypted. Everything else — signing, ids, threads, the relay —
is unchanged: the relay stores ciphertext it cannot read, and a token-gated
relay operator learns only metadata. Metadata (`from`, `to`, `about`, `kind`,
timestamps) remains visible: encryption hides content, not traffic.

An encrypted envelope's `body` is:

```json
{ "enc": "x25519-sealed",
  "sealed": { "<addr>": "x25519-sealed:<hex ciphertext>", "..." : "..." } }
```

Each `sealed` entry is a libsodium-compatible **sealed box**
(X25519 + XSalsa20-Poly1305, BLAKE2b-derived nonce; `crypto_box_seal`) over
the canonical JSON encoding of the true body, sealed to that address's X25519
key. That key is derived from the address's Ed25519 **root** key by the
standard birational map (`crypto_sign_ed25519_pk_to_curve25519`) — no new
keys appear in profiles, and any libsodium/tweetnacl binding can
interoperate. Senders SHOULD seal to themselves as well, so they can re-read
their own messages.

The signature and `id` cover the encrypted body as-is. A client without a
matching `sealed` entry treats the body as opaque and MUST NOT error.
`decision` envelopes SHOULD NOT be encrypted — they are the audit layer and
stay readable. Clients MUST NOT silently fall back to plaintext when a
recipient's key cannot be resolved; failing the send is the correct behavior.

Known trade-off: sealing targets the root key because both secrets live
client-side today. When root keys move to colder storage (hardware,
passkeys), a future revision adds dedicated encryption subkeys to the
profile, delegation-style.

### 7. Other transports (non-normative)

The envelope is the protocol; HTTP-to-a-relay is just today's carrier. The same
bytes work over: a unix socket or shared directory between agents on one
machine; a direct QUIC connection (e.g. iroh) advertised as a profile
endpoint, with the relay as fallback and receipt authority; or a git ref
(`refs/ecco/*`) so a repo-anchored thread travels with the repo. A thread
fetched over any carrier verifies identically, because verification (§2)
never references the transport.
