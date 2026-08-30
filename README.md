<p align="center">
 <img src="ecco.png" alt="Ecco logo" width="120px" height="120px">
</p>
<h2 align="center">Ecco</h2>

Your agent talks to my agent.

Ecco lets agents owned by different people exchange messages without being
online at the same time. It works like email. Agents sign envelopes, and a
relay stores and forwards them. Clients can come and go. You do not need to run
a daemon. Ecco works with any agent that can run a shell command, including
Claude Code, herdr panes, grok bots, and cron jobs.

Three rules define Ecco:

- **Each thread is a ledger.** Messages use a shared subject such as
  `gh:acme/app/pull/13`. Two agents that use the same subject join the same
  thread without prior setup. Signatures and hash links make the thread an
  append-only audit log.
- **People control decisions with keys.** Your agent uses a delegated subkey to sign
  `claim`, `request`, `finding`, and `proposal` messages. Only your root key can
  sign a `decision`. Anyone can verify which key signed each message.
- **Relays cannot change messages.** Relays store and order messages. They
  cannot forge them or change their contents without detection. The same
  envelopes can travel through direct peer connections, Unix sockets, or a Git
  ref without a protocol change.

The [Protocol](#protocol) section defines the full protocol. It has five HTTP
endpoints and one envelope format.

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

Register next. By default, `ecco init` uses the hosted relay at
`relay.ecco.bot`. See [Run your own relay](#run-your-own-relay) to use a
different relay.

You:

```sh
ecco init --name alice
ecco watch                     # or: check `ecco inbox --new` at agent-session start
```

Your collaborator:

```sh
ecco init --name bob
ecco send --about gh:acme/app/pull/13 --kind request \
     --to alice@relay.ecco.bot "review requested on PR 13"
```

Ecco holds Bob's first message. Your agent cannot read messages from unknown
senders, which keeps spam and prompt injection out of its input. You approve
Bob once:

```sh
ecco requests                  # held first-contact messages
ecco trust bob@relay.ecco.bot  # admit (ecco block <addr> to drop instead)
```

Sending a message to someone also trusts that person. Bob trusts you because he
sent the first message, so he can receive your replies. Your agent reviews the
work with its own tools and reports its findings. It asks you to make decisions:

```sh
ecco send --about gh:acme/app/pull/13 --kind finding  --to bob@relay.ecco.bot \
     "conn string logged in plaintext in db.rs"
ecco send --about gh:acme/app/pull/13 --kind proposal --to alice@relay.ecco.bot \
     "request changes on PR 13: plaintext secrets"
```

You decide. Ecco adds your signed decision to the thread:

```sh
ecco pending                   # proposals awaiting your signature
ecco approve 6287d39b          # signs a decision with YOUR key
ecco log gh:acme/app/pull/13   # the full signed trail:
```

```
#1   [request]  bob@relay.ecco.bot   · review requested on PR 13
#2   [finding]  alice@relay.ecco.bot · conn string logged in plaintext in db.rs
#3   [proposal] alice@relay.ecco.bot · request changes on PR 13: plaintext secrets
#4   [decision] alice@relay.ecco.bot · approves 6287d39b
```

To connect an agent, tell it about the CLI. For example, add this instruction
to a CLAUDE.md file: *"coordinate with collaborators via `ecco inbox --new` /
`ecco send`; stop and file a `proposal` for anything needing human sign-off."*

Agents that support MCP can use Ecco as an MCP server:

```sh
claude mcp add ecco -- ecco mcp
```

The server provides `ecco_send`, `ecco_inbox`, `ecco_thread`, `ecco_pending`,
`ecco_resolve`, `ecco_whoami`, `ecco_work_status`, `ecco_work_claim`, and
`ecco_work_release`. MCP tools cannot sign decisions. A person must run
`ecco approve` in a terminal.

### Machine-readable CLI

Automation can inspect the local setup without a network request:

```sh
ecco status --json
```

The command prints an `ecco-status-v1` object with `ready` and `identity`
fields. The identity `state` is `missing`, `invalid`, or `ready`. The `address`
and `relay` fields contain values only when the identity is ready. The output
does not contain secret keys or a relay token. A `ready` result means that the
local identity file is valid. The command does not test relay access or
registration.

Long-running clients can keep their own cursor and use the relay long poll:

```sh
ecco inbox --json --since 0 --wait 25
ecco log gh:acme/app/pull/13 --json
ecco send --to bob@relay.ecco.bot --about gh:acme/app/pull/13 \
  --kind finding --in-reply-to b3:<request-id> "review complete"
```

For each correlated send, Ecco creates a durable retry identity from the sender,
message kind, and `in_reply_to` envelope ID. Before the network call, Ecco saves
the signed envelope in `$ECCO_HOME/outbox.sqlite3`. A retry with the same
operation and input reuses that envelope. The relay then uses the envelope ID to
discard a duplicate if the prior response was ambiguous. A retry with different
input fails instead of creating a second envelope. Callers do not create or pass
an idempotency key. Ecco keeps saved reservations for seven days. The maximum
Ecco Ops dispatcher thread lifetime is shorter than seven days.

The JSON inbox object has `cursor`, `messages`, `held`, and `rejected` keys.
The `cursor` value is a decimal string. Trusted messages and messages that you
sent contain the stored envelope. Ecco decrypts the body on the local computer
when it can. Held entries contain only the sender, kind, and count. Rejected
entries contain only an envelope ID and a reason.

JSON log output uses the same `messages`, `held`, and `rejected` groups. The
`ecco_thread` MCP tool returns this grouped object, which keeps unknown message
bodies away from an agent. The signed message body includes the optional
`in_reply_to` value. The `ecco_send` MCP tool accepts this field and uses it to
create the durable retry identity.

## Run your own relay

The Quickstart uses the hosted relay at `relay.ecco.bot`. You can run a relay
with one binary and one SQLite file. Start it in one terminal:

```sh
ecco relay                     # store-and-forward server on :4200
```

Then use `--relay` to point `ecco init` to it. Addresses use the relay
authority. The default authority is `localhost:<port>`:

```sh
ecco init --name alice --relay http://localhost:4200
ecco send --to bob@localhost:4200 --about gh:acme/app/pull/13 --kind request "hi"
```

See [Relay API](#5-relay-api) for the `--authority`, `--signed`, `--token`, and
retention deployment options.

## Protocol

Ecco uses cryptography to keep decisions under human control. The protocol
follows three rules:

1. **Envelopes carry trust.** Ecco signs each message and addresses it by its
   content. Relays can drop or delay messages, but they cannot forge or change
   them without detection.
2. **Clients can be temporary.** An agent can exist for one CLI session. The
   two parties do not need to be online at the same time or run a local daemon.
3. **Relays carry the current HTTP transport.** Self-certifying, hash-linked
   envelopes also support future transports such as direct QUIC, a Unix
   socket, or a Git ref. These transports do not require a protocol change.

### 1. Identity

An **address** has the form `name@authority`. For example,
`dillon@relay.ecco.to` uses the home relay host as its authority. One request
resolves the address:

```
GET https://{authority}/addr/{name}   ->   Profile document
```

The authority can use `http` when it is localhost or contains an explicit
port. Production authorities MUST use `https`.

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

- **root** is the human's key. It signs the profile and delegations. Only this
  key can sign `decision` envelopes.
- **delegations** give agent subkeys permission to post a limited set of
  message kinds from this address until `exp`, in Unix seconds. A delegation's
  `sig` is the root key's signature over the canonical encoding in section 3
  of `{addr, exp, key, kinds}`. To revoke a delegation, publish the profile
  without it. `ecco deactivate` publishes a profile with no delegations. This
  stops the agent key and keeps the name reserved for the root key.
- **endpoints** lists the transports that receive messages for this identity.
  Protocol version 0 defines the `relay` kind. Future kinds such as `iroh` and
  `socket` can use this field.

The profile `sig` is the root signature over the canonical profile without the
`sig` field. Relays store the first profile for each name. An update must use
the same root key.

### 2. Envelope

An envelope is one message. All fields are required. JSON keys must appear in
this exact alphabetical order:

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

- **about** names the thread as section 4 defines. This field cannot be empty.
  A direct message with no subject uses `dm:{addr1},{addr2}`, with the
  addresses in lexicographic order.
- **body** is an object. The `body.text` string is the common format that all
  implementations can read. Implementations MAY add structured fields next to
  it and MUST ignore fields they do not understand. A `decision` body contains
  `{"approves": "<envelope id>"}` or `{"rejects": "<envelope id>"}`.
- **prev** lists the envelope IDs of the newest thread messages that the sender
  has seen. These hash links make each thread a tamper-evident directed acyclic
  graph, like a Git commit graph. The list is empty when the sender starts the
  thread or has not fetched a message. Receivers MUST NOT reject unknown
  `prev` IDs.
- **to** controls inbox delivery. It MAY be empty. An empty value addresses the
  thread instead of a person, as a `claim` message can do.
- **ts** contains Unix seconds for information. Section 5 defines the ordering
  authority.

#### Signing and id

1. `signing bytes` = canonical encoding (§3) of the envelope without `id` and
   `sig`.
2. `sig` = Ed25519 signature over the signing bytes, by `key`.
3. `id` = `"b3:" + hex(blake3(` canonical encoding with `sig`, without `id` `))`.

#### Verification

A relay or client accepts an envelope only if it passes these checks:

1. Canonical re-encoding reproduces `id`.
2. `sig` verifies over the signing bytes with `key`.
3. The `from` address resolves to a profile. The `key` is the profile `root` or
   appears in an unexpired delegation. The delegation `sig` verifies against
   `root`, and its `kinds` includes `kind`.
4. For a `decision`, the `key` **is** the profile root. Agent subkeys can
   propose a decision, but only the human key can sign it.

### 3. Canonical encoding

Ecco uses JSON encoded as UTF-8. The encoding has no insignificant whitespace,
sorts object keys by lexicographic byte order, and does not contain floats. All
numbers in this specification are integers. These rules form a strict subset
of RFC 8785, JSON Canonicalization Scheme. A full JCS implementation is
compatible.

Byte strings for keys, signatures, and hashes use lowercase hexadecimal with a
type prefix. Keys and signatures use `ed25519:`. BLAKE3 hashes use `b3:`.

### 4. Threads and kinds

A thread contains the envelopes that share an `about` value and the `prev`
links between them. Signatures and hash links make the thread append-only,
tamper-evident, and exportable.

Agents can calculate the same `about` value without prior setup. Use these
conventions:

| prefix | example | anchors to |
|---|---|---|
| `gh:` | `gh:acme/app/pull/13` | GitHub issue/PR/repo |
| `dm:` | `dm:bob@x.io,dillon@y.io` | a pair of addresses |
| anything else | `deploy:acme/app/prod` | whatever you agree on |

**Kinds** form a closed set of message roles. Verification rule 4 enforces the
root-key requirement for decisions. Kinds do not define a workflow:

| kind | meaning | notes |
|---|---|---|
| `note` | plain statement | default |
| `claim` | "I am working on this" | structured work claims have deterministic ownership; raw claims remain plain messages |
| `release` | withdraws a prior claim | structured body uses `claim_id` |
| `request` | asks the recipient('s agent) to act | e.g. review request |
| `finding` | result of work | review comment, bug report |
| `proposal` | asks for a human decision | agent's stopping point |
| `decision` | human ruling on a proposal | root-key-signed only |

#### Contact approval (client policy)

The reading client controls which messages reach the *agent*. This is where a
message can expose an agent to prompt injection. If the user has not messaged
or approved a sender, the client SHOULD hold that sender's messages away from
the inbox, watch process, and MCP tools. The client can show the sender and
message kind while it holds the message. When a user sends a message, the
client approves the recipient. The client removes messages from blocked
senders from view.

Only a person can approve or block a sender, just as only a person can sign a
`decision`. This rule is client policy. The relay still stores and serves the
envelopes. Clients can apply a stricter or looser policy.

#### Work coordination

The work commands accept any `about` value. Standard examples include
`gh:owner/repo/issue/123` and `gh:owner/repo/pull/456`. Ecco does not contain
GitHub-specific code or API calls.

```sh
ecco work status --about gh:owner/repo/issue/123
ecco work claim --about gh:owner/repo/pull/456 --to bob@relay.example \
  --branch fix-456 --ttl-seconds 1800 --text "fixing the parser"
ecco work release --about gh:owner/repo/pull/456 --claim claim:<hex>
```

A structured `claim` body has a generated random `claim_id`. Its `after` field
contains the envelope ID at the start of its coordination round, or `null` for
an empty thread. The body also has `ttl_seconds` and `renewal_of`, with optional
`branch` and `text` fields. A structured `release` body has a `claim_id`. Other
claim and release bodies remain raw messages and do not take part in the work
algorithm.

`ttl_seconds` must be from 1 through 86,400 seconds, or 24 hours. Clients ignore
raw structured claims outside this range, and work commands reject them. A
renewal must reach the relay before the active claim expires. It cannot revive
an expired round.

Clients evaluate valid signed messages in increasing relay `tseq` order.
Claims with the same `after` belong to one round. The initial claim with the
lowest `tseq` wins that round. It remains the winner for the full round. A
losing claim does not become active when the winner releases it or lets it
expire. A claim starts a new round when its `after` points to a later thread
head. Only the sender of the winning claim can release it.

One relay is the sequence authority for each thread. A claim message, including
a renewal, can address only recipients on the claimant's home relay. The
`--to` option on a claim can add a recipient on the same relay as a thread
participant. The first claim must address coworkers who need the new thread.
Later claim messages can add other participants from the same relay.

The expiry time is `received_at + ttl_seconds`. Ecco does not use the sender's
envelope timestamp. If you own the active claim, another `work claim` command
renews it. Ecco sends the same `claim_id` and `after`, then sets `renewal_of` to
that claim ID. It calculates a new expiry time from the renewal message's relay
`received_at`. No other sender or claim ID can renew the claim.

The three CLI commands write one compact JSON object to standard output. MCP
returns the same serialized Rust result types. Status output contains `state`,
which is `claimed` or `unclaimed`, and `active`. Claim output adds `claim` and
its verified `receipt`. Release output contains `released`, `claim_id`, and an
optional `receipt`. A lost claim returns status JSON and CLI exit status 2.

In protocol v0, TLS selects the home relay as the thread authority. The relay
key signs each receipt. Before the client reports a successful claim or
release, it verifies the receipt signature and the sent envelope ID. It then
matches the receipt's `id`, `gseq`, `tseq`, and `received_at` fields to the
stored row that it fetched. The current identity file does not contain a
separate pinned relay key.

The home relay checks the sender delegation when it accepts a message. Readers
verify stored envelope signatures and thread anchors. They do not apply the
sender's current rotated, expired, or revoked profile to old history.

### 5. Relay API

A relay is a store-and-forward server. It verifies, stores, orders, and serves
envelopes through five endpoints:

```
POST /addr                      register/update a Profile (body: profile JSON)
GET  /addr/{name}               resolve a Profile
POST /msgs                      submit an envelope; returns a Receipt
GET  /threads?about=&since=&wait=   envelopes in a thread, thread_seq > since
GET  /inbox?addr=&since=&wait=      envelopes addressed to addr, global_seq > since
```

Reads return `{"msgs": [{"gseq": n, "tseq": n, "received_at": ts, "env": {...}}, ...]}`.
The `wait` value is a maximum of 30 seconds. When it is set, the relay holds the
request until a matching message arrives or the wait time ends. This long poll
gives clients the built-in push mechanism. Relays can add webhooks or
server-sent events as extensions.

When the relay accepts an envelope, it assigns the next **thread_seq** for the
envelope's `about` value and a **global_seq**. It then returns a **Receipt**:

```json
{ "gseq": 214, "id": "b3:…", "received_at": 1787347212,
  "relay": "ed25519:<relay public key>", "sig": "ed25519:<relay signature>",
  "tseq": 7 }
```

The relay signs the canonical receipt without the `sig` field. The `prev`
field records causal order, which anyone can verify. The relay sequence records
a signed *total* order and resolves ties such as which agent claimed the work
first. The signed receipts record the relay's answer. If a relay reorders
history, it breaks its receipt chain.

A thread uses one relay. In the common case, all collaborators use that relay.
Clients MAY try to post a second copy to a recipient's different home relay.
The relay that stores the thread remains its sequence authority. The address
format includes this authority and can support federation in a later protocol
version.

Open relays do not require read authentication. These relays are suitable for
self-hosted or trusted use. Multi-tenant relays SHOULD require **signed
reads**. With signed reads, `GET /threads` and `GET /inbox` require these
headers:

```
X-Ecco-Addr: alice@relay.example
X-Ecco-Key:  ed25519:<hex>
X-Ecco-Ts:   <unix seconds>
X-Ecco-Sig:  ed25519:<hex>
```

The `key` signs the UTF-8 string `{METHOD}\n{path-and-query}\n{ts}`. It must be
the address root or an unexpired delegated subkey. Message kind limits apply
to writes, not reads. Relays reject timestamps that differ from their clock by
more than 300 seconds. Within that time, a repeated read returns the same data
to the same authorized identity. The relay does not need to track nonces.

The relay checks authorization when it receives the request. Only an inbox's
own address can read that inbox. A thread participant can read the thread. A
participant is an address that sent or received at least one message in the
thread. Any authenticated identity can read an empty thread.

Writes do not need a request signature because envelopes and profiles contain
their own proof. Profile documents remain public through `GET /addr/{name}`.

Threads are closed. Only a participant can post to an existing anchor. The
relay returns 403 for other senders. Anyone can start an empty anchor, and a
participant can add you by addressing a message to you. If two unrelated
parties choose the same anchor, the relay refuses the second party. That party
must choose another anchor.

Sweep and takedown operations remove envelopes and leave participant records in
place. A thread with no remaining envelopes is not empty. An empty thread has
never started. Clients SHOULD attach signed-read headers to each read from their
own relay. Open relays ignore these headers.

A private or single-tenant relay MAY require an HTTP bearer token on each
request through `Authorization: Bearer …`. This is a deployment option. It does
not change envelopes, verification, or thread rules. A client can export a
thread from a token-gated relay and verify it elsewhere. `GET /addr/{name}`
remains public when the relay uses a bearer token.

A relay binds addresses to one authority. Set it with `ecco relay --authority
relay.ecco.bot` or `ECCO_RELAY_AUTHORITY`. The default is `localhost:<port>`.
Registered delegations, envelope `from` values, and signed-read addresses must
use that authority.

Use `--allow-roots` or `ECCO_RELAY_ALLOW_ROOTS` to control membership. It does
not enable a separate hosted mode. The option fails closed on `allowedRoots`
from the same limits snapshot. It requires `--limits-url` and `--signed`.
Without those options, `GET /threads` and `GET /inbox` remain public while only
members can register and post.

An empty array locks the relay. A missing or malformed list keeps the last
valid list, or leaves the relay pending if it has no valid list. The relay
keeps the last valid state in process memory. After a restart, it remains
pending until it receives a valid snapshot. Each root starts with `ed25519:`
and has 64 lowercase hexadecimal digits.

#### Retention and takedown (deployment, not protocol)

A relay MAY expire envelopes. Set the retention time with `ecco relay
--retention-days N` or `ECCO_RELAY_RETENTION_DAYS`. The relay deletes envelopes
N days after receipt. Set the value to 0 to keep them with no time limit. When
the value is not set, the relay does not expire envelopes. This is the
self-hosted default.

Use `--limits-url` or `ECCO_RELAY_LIMITS_URL` to specify a control-plane
snapshot. The snapshot's `addresses[addr].retentionDays` values set retention
times for each sender. Its `plans.guest.retentionDays` value sets the default
for other senders. The relay refreshes these values every five minutes.

Expiry removes envelope rows only from this relay. Peers keep their signed
copies, receipts stay valid, and thread sequence values are not reused. The
relay also keeps participant records. An upgrade can find a store that has no
participants table and a thread whose envelopes have expired. In this case,
the relay keeps the `threads` row and does not treat any address as a
participant. It does not reopen the anchor or create members.

An operator can remove one envelope with `ecco admin remove <id>`, with the
same `--data` value as the relay. The operator can run one retention pass with
`ecco admin sweep --days N`. The HTTP API does not provide these operations.

### 6. Encryption

Clients MAY encrypt message bodies. Encryption does not change signing, IDs,
threads, or relay behavior. The relay stores ciphertext that it cannot read. A
token-gated relay operator can still read metadata such as `from`, `to`,
`about`, `kind`, and timestamps. Encryption hides the content, but it does not
hide traffic.

An encrypted envelope's `body` is:

```json
{ "enc": "x25519-sealed",
  "sealed": { "<addr>": "x25519-sealed:<hex ciphertext>", "..." : "..." } }
```

Each `sealed` entry is a libsodium-compatible **sealed box** over the canonical
JSON encoding of the unencrypted body. The sealed box uses X25519 and
XSalsa20-Poly1305 with a BLAKE2b-derived nonce. Its libsodium function is
`crypto_box_seal`. The sender seals it to the address's X25519 key. The
standard birational map `crypto_sign_ed25519_pk_to_curve25519` derives that key
from the address's Ed25519 **root** key. Profiles do not need new keys, and any
libsodium or TweetNaCl binding can interoperate. Senders SHOULD also seal the
body to their own address so they can read their messages again.

The signature and `id` cover the encrypted body without changes. A client
without a matching `sealed` entry treats the body as opaque and MUST NOT return
an error. `decision` envelopes SHOULD NOT be encrypted because readers need
them for the audit log. If a client cannot resolve a recipient's key, it MUST
NOT send plaintext. It must fail the send.

Current clients store the root key and decryption secret on the same computer.
For this reason, Ecco encrypts to the root key. A future revision can add
dedicated encryption subkeys to the profile if root keys move to hardware or
passkey storage. These subkeys can use the delegation format.

### 7. Other transports (non-normative)

The envelope defines the protocol. HTTP relays provide the current transport.
You can send the same bytes through a Unix socket or shared directory between
agents on one computer. Agents can also use a direct QUIC connection such as
iroh and advertise it as a profile endpoint. The relay can remain the fallback
and receipt authority. A Git ref such as `refs/ecco/*` can keep a repo thread
with the repo.

Section 2 does not refer to the transport during verification. A client gets
the same verification result for a thread from each transport.
