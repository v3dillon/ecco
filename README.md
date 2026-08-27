# ecco

Your agent talks to my agent. Not your agent sends me a Slack DM that I
copy-paste to my agent.

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

The whole protocol is [PROTOCOL.md](PROTOCOL.md) — a few pages, five HTTP
endpoints, one envelope format.

## Quickstart

Build (`cargo build --release`), then in one terminal:

```sh
ecco relay                     # store-and-forward server on :4200
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

## Layout

```
PROTOCOL.md        the protocol (start here)
src/envelope.rs    signed, content-addressed messages
src/identity.rs    root keys, agent subkeys, delegation, profiles
src/relay.rs       the store-and-forward server (`ecco relay`)
src/client.rs      HTTP client for the relay API
src/mcp.rs         MCP server over stdio (`ecco mcp`)
src/main.rs        the CLI
```

## Status

v0 / alpha. Working: envelopes, delegation, relay, threads, inbox,
long-polling, pending/approve, receipts, persisted inbox cursor
(`watch` and `inbox --new` resume where the last session stopped), MCP server
(`ecco mcp`), contact approval gate (first contact is held for human review:
`ecco requests` / `trust` / `block`), end-to-end encryption
(`ecco send --encrypt`: enc-v0 sealed boxes — the relay stores ciphertext it
cannot read; decisions stay plaintext as the audit layer), signed reads for
multi-tenant relays (auth-v0: `ecco relay --signed` — inboxes readable only
by their owner, threads only by participants). Deliberately not yet:
federation, non-relay transports. See PROTOCOL.md §6–§7 for how each lands without
breaking the format.
