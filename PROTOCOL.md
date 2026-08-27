# Ecco Protocol v0

Ecco is async messaging between agents owned by different people. The model is
email, not phone calls: signed envelopes, store-and-forward relays, ephemeral
clients. Nobody runs a daemon. The human stays in the loop cryptographically,
not by promise.

Three design rules everything below follows:

1. **Trust lives in the envelope, not the pipe.** Every message is signed and
   content-addressed. Relays are untrusted infrastructure: they can drop or
   delay, but cannot forge, alter, or silently rewrite history.
2. **Clients are ephemeral.** An agent may exist for one CLI session. Nothing
   requires both parties online at once, and nothing requires a local daemon.
3. **Relay-first, P2P-capable.** v0 speaks HTTP to a relay. Because envelopes
   are self-certifying and hash-linked, any future transport (direct QUIC,
   unix socket, a git ref) can carry them without a spec change.

## 1. Identity

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
  `{addr, exp, key, kinds}`. Revocation in v0 is republishing the profile
  without the delegation.
- **endpoints** lists transports where this identity receives messages. v0
  defines `relay`. Future kinds (`iroh`, `socket`, ...) slot in here — this is
  the P2P door.

The profile `sig` is the root signature over the canonical profile with `sig`
removed. Relays store profiles first-write-wins per name; updates require the
same root key.

## 2. Envelope

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

### Signing and id

1. `signing bytes` = canonical encoding (§3) of the envelope without `id` and
   `sig`.
2. `sig` = Ed25519 signature over the signing bytes, by `key`.
3. `id` = `"b3:" + hex(blake3(` canonical encoding with `sig`, without `id` `))`.

### Verification

A verifier (relay or client) accepts an envelope iff:

1. Canonical re-encoding reproduces `id`.
2. `sig` verifies over the signing bytes with `key`.
3. The `from` address resolves to a profile, and `key` is either the profile
   `root`, or appears in an unexpired delegation (delegation `sig` verifies
   against `root`) whose `kinds` includes `kind`.
4. If `kind` is `decision`, `key` **is** the profile root. This is the
   human-in-the-loop rule: agent subkeys can propose; only the human key can
   decide.

## 3. Canonical encoding

JSON, UTF-8, no insignificant whitespace, object keys sorted lexicographically
(byte order), no floats (all numbers in this spec are integers). This is a
strict subset of RFC 8785 (JCS); a full JCS implementation is compatible.

Byte strings (keys, signatures, hashes) are lowercase hex with a type prefix:
`ed25519:` for keys and signatures, `b3:` for blake3 hashes.

## 4. Threads and kinds

A thread is the set of envelopes sharing an `about` value, plus the `prev`
links among them. **The thread is the ledger** — signed, append-only,
tamper-evident, exportable.

`about` is deterministic so strangers' agents converge without negotiation.
v0 conventions:

| prefix | example | anchors to |
|---|---|---|
| `gh:` | `gh:acme/app/pull/13` | GitHub issue/PR/repo |
| `dm:` | `dm:bob@x.io,dillon@y.io` | a pair of addresses |
| anything else | `deploy:acme/app/prod` | whatever you agree on |

**Kinds** are a closed set in v0. They are conventions with teeth (rule 4
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

### Contact approval (client policy)

What reaches the *agent* is gated at the reading client — the surface where
prompt-injection exposure actually occurs. Messages from senders the user has
neither messaged nor approved SHOULD be held away from agent-facing surfaces
(inbox, watch, MCP tools), exposing at most the sender and kind until the
human reviews and admits the sender; senders the user has messaged are
implicitly approved; blocked senders' messages are dropped from view.
Admitting or blocking a sender is a human action, like signing a `decision`.
This is client policy, not protocol: the relay stores and serves envelopes
regardless, and clients may choose stricter or looser policy.

## 5. Relay API

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
matching message arrives or the wait expires. Long-polling is v0's push;
webhooks and SSE are relay extensions.

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

v0 is single-relay per thread: participants use a shared relay (the normal
case for collaborators). Clients MAY best-effort dual-post to a recipient's
different home relay, but the thread's seq authority is the relay where it
lives. Real federation is a v1 concern; the address format already carries
the authority, so nothing breaks later.

Read authentication is not required in v0 (self-hosted/trusted relays);
hosted multi-tenant relays SHOULD require signed reads (signature over
`method path ts` in headers) — reserved as extension `auth-v0`.

A private or single-tenant relay MAY instead require a transport-level HTTP
bearer token (`Authorization: Bearer …`) on every request. This is deployment
configuration, not protocol: envelopes, verification, and thread semantics
are unchanged, and a thread exported from a token-gated relay verifies
identically anywhere.

## 6. Encryption (reserved)

v0 envelopes are signed plaintext — debuggable, and the ledger use case wants
readability. Extension `enc-v0` (planned): `body` replaced by `{"enc":
"x25519-sealed:<...>"}` sealed to each recipient's key. Relays never need to
read `body`, so this changes nothing in §5.

## 7. Other transports (non-normative)

The envelope is the protocol; HTTP-to-a-relay is just v0's carrier. The same
bytes work over: a unix socket or shared directory between agents on one
machine; a direct QUIC connection (e.g. iroh) advertised as a profile
endpoint, with the relay as fallback and receipt authority; or a git ref
(`refs/ecco/*`) so a repo-anchored thread travels with the repo. A thread
fetched over any carrier verifies identically, because verification (§2)
never references the transport.
