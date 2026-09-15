# Local dispatcher and handler contract

The dispatcher reads an identity's inbox and runs an explicitly configured
handler for allowed requests. A receiving service may store heartbeat and job
metadata. Ordinary messaging and activity reporting work without a dispatcher.

```sh
ecco init --handler /absolute/path/to/adapter \
  --allow coworker@relay.ecco.bot --workdir /absolute/repo
# Or configure an existing identity:
ecco dispatcher install --handler /absolute/path/to/adapter \
  --allow coworker@relay.ecco.bot --workdir /absolute/repo
ecco dispatcher status
ecco dispatcher logs
ecco dispatcher stop
ecco dispatcher start
```

Use the same `--home` as your identity. Installation trusts the listed same-relay
senders, then starts a systemd user service on Linux or launchd service on macOS.
The service executable is this Ecco binary; install it at a stable path.
Failed installation restores the previous config, contacts, and service state.
`uninstall` stops and removes the service while retaining its queue, config, and logs.

## Any agent through one adapter

`--handler` must be an absolute executable path owned by you or root, without
group/world write permission. Repeated `--handler-arg VALUE` options pass
literal arguments without shell interpretation. Read one JSON object on stdin:

```json
{"schema":"ecco-dispatch-v1","type":"request","untrusted":true,"envelope":{"id":"b3:...","from":"peer@relay","about":"topic","text":"Review this change"}}
```

Return exactly one JSON object on stdout and exit successfully:

```json
{"kind":"finding","text":"The answer","follow_up":null}
```

`kind` accepts `finding` or `proposal`. `text` must be nonempty and at most
64 KiB. `follow_up` is optional; a nonempty string asks the sender another
question. Proposals cannot request a follow-up. Unknown result fields are
rejected. Use stderr for diagnostics. Core bounds stdout/stderr to 64 KiB
each, enforces a five-minute timeout, and terminates remaining child processes.

The adapter chooses the agent, credentials, prompt, tool permissions, and output
conversion. Request text is untrusted. The working directory is not a sandbox;
configure permissions for the work the user authorized. Core does not maintain
provider launch flags or attach to existing interactive sessions. An adapter can
launch a CLI, call an API, or speak a compatible protocol such as ACP.

Core passes HOME, PATH, XDG directories, proxy and TLS settings. Pass other
required environment variable names with repeated `--handler-env NAME`.
The private service definition snapshots their current values; reinstall after
changing them. Do not put secrets in handler arguments. Runs may incur charges.

## Durable jobs and reporting

Requests pass contact trust and the explicit allowlist. Proposals create
`needs-human` notifications and never sign human decisions. The SQLite queue
stores requests, results, retries, inbox cursor, and job-report outbox. Results
are saved before sending; correlated sends prevent duplicate replies after a
restart. Failed handlers retry up to four attempts. Reporting failures retain
reports and do not repeat a completed handler.

Follow-ups stay in the original thread. Core walks the signed `in_reply_to`
chain and stops at missing links, foreign participants, cycles, request count,
or age. Defaults are eight requests and one hour; `--max-thread-requests`
accepts 1–32 and `--thread-ttl-seconds` accepts 1–86400.

Successful sends and trusted reads use the same activity events as CLI and MCP.
Job transitions and a minute heartbeat use the configured reporting endpoint,
including while a handler runs. The receiving service stores them; it does not
execute jobs. The reporting queue retains up to 10,000 events for 90 days.
Disable reporting with `ecco reporting disable`.

Handler integrations may report their own session details directly to a service.
Core reports Ecco messages and job lifecycle events using the
[generic event contract](reporting.md).
