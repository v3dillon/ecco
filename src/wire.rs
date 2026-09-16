// Every versioned identifier that crosses a process boundary, in one place.
// Bump a version here; nothing else in the tree spells one out. The service
// side mirrors this list in ecco-ops packages/trace/src/versions.ts.

/// Envelope `v` (README §2).
pub const ENVELOPE_V: u8 = 0;
/// Profile `v` (README §1).
pub const PROFILE_V: u8 = 0;
/// Message a root key signs to connect an identity to a registration service.
pub const CONNECT: &str = "ecco-connect-v1";
/// Message a root key signs to offer an unmanaged relay name to another root.
pub const TRANSFER: &str = "ecco-transfer-v1";
/// What a relay POSTs to its operator's reporting endpoint.
pub const ACTIVITY: &str = "ecco-activity-v1";
/// What the dispatcher writes to a handler's stdin.
pub const DISPATCH: &str = "ecco-dispatch-v1";
/// `ecco status --json`.
pub const STATUS: &str = "ecco-status-v1";
/// Capability advertised by `ecco status`: correlated sends are idempotent.
pub const DURABLE_CORRELATED_SEND: &str = "durable-correlated-send-v1";
