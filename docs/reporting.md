# Optional activity reporting

Core reports Ecco operations; a receiving service owns its storage and presentation.
Reporting is optional and independent of the messaging protocol.

```sh
ecco reporting configure --endpoint https://service.example/events
ecco reporting status
ecco reporting retry
ecco reporting disable
```

`ecco init --report-to URL` sets the same full endpoint; `--no-reporting` disables
it. Init preserves existing choices. A relay may advertise `reporting_url` in
`GET /.well-known/ecco`, configured by `ECCO_REPORTING_URL`. If a hosted relay
advertises only `registration_url`, core also reads the registration service's
`/.well-known/ecco` for its optional reporting URL. Core never constructs a
service-specific API path. URLs require HTTPS, except loopback HTTP for tests;
credentials, queries, fragments, and redirects are rejected.

## Event payloads

Each request is JSON with `schema: "ecco-activity-v1"` and the reporting identity's
`observer` address. A message observation has this shape:

```json
{"schema":"ecco-activity-v1","type":"message","observer":"alice@relay.test","envelope":{"id":"b3:...","about":"topic","from":"alice@relay.test","to":["bob@relay.test"],"kind":"note","text":"hello","encrypted":false},"receipt":{"gseq":10,"tseq":1,"received_at":1789413000}}
```

These are observations, not copies of signed envelopes. Core emits them after
verifying the relay receipt on send or envelope signature on read and applying
contact trust. `text` is null for encrypted messages; neither ciphertext nor
decrypted bodies leave core. Receipt timestamps use Unix seconds. Repeated
observations of the same stored message produce identical payload bytes.

A dispatcher event has `type: "dispatcher"` and `report` containing its versioned
batch: `{v:1, events:[...], heartbeat:{v:1, dispatcherId, provider, at}}`. Job
events contain `v`, `eventId`, `dispatcherId`, `jobId`, `sequence`, `state`,
`provider`, `attempt`, `at`, and `about`. `provider` is the handler's label.
The dispatcher batches up to 100 transitions and sends a heartbeat every minute.
See [dispatcher semantics](dispatcher.md) for states, retries, and limits.

## Signed delivery

POST to the configured endpoint with `content-type: application/json` and:

- `x-ecco-addr`: observer address
- `x-ecco-key`: delegated public key
- `x-ecco-ts`: current Unix seconds
- `x-ecco-sig`: Ed25519 signature over `POST\n<URL path>\n<timestamp>\n<SHA-256 hex of body>`

After durable ingestion, the service returns a successful JSON response:
`{"accepted":"sha256:<SHA-256 hex of exact request body>"}`. This acknowledges
delivery without exposing the service's internal storage identifiers.

Messages wait under `$ECCO_HOME/reporting-outbox`, scoped to endpoint, address,
and root key. Files are private and removed only after a matching acknowledgement.
Concurrent workers serialize delivery and collect events queued while they run.
Failures remain pending; they never change a successful Ecco operation. A rejected
event does not block other events. Explicit retry displays errors. Background
workers stop between requests when reporting is disabled or its endpoint changes.
