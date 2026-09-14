//! Generic upload interface. Agent integrations supply files; core never discovers sessions.
use crate::{local, reporting};
use clap::Subcommand;
use serde_json::json;
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum TraceCmd {
    /// Enable private Ecco activity reporting to a service
    Configure {
        #[arg(long)]
        api: String,
    },
    /// Stop automatic activity uploads; retain pending uploads locally
    Disable,
    Status,
    /// Upload canonical JSONL, or a transcript in a service-supported format
    Push {
        #[arg(
            long,
            required_unless_present = "transcript",
            conflicts_with = "transcript"
        )]
        trace: Option<PathBuf>,
        #[arg(long, requires = "from")]
        transcript: Option<PathBuf>,
        /// Transcript format understood by the service (no built-in agent registry)
        #[arg(long, requires = "transcript")]
        from: Option<String>,
        #[arg(long, requires = "transcript")]
        turn_id: Option<String>,
        #[arg(long, requires = "transcript")]
        thinking: bool,
        #[arg(long)]
        api: Option<String>,
    },
    /// Retry retained uploads; failures stay queued
    Retry {
        #[arg(long)]
        api: Option<String>,
        #[arg(long, hide = true, conflicts_with = "api")]
        background: bool,
    },
}
pub fn run(home: &Path, cmd: TraceCmd) -> Result<(), String> {
    match cmd {
        TraceCmd::Configure { api } => {
            reporting::configure(home, Some(&api))?;
            reporting::status(home)
        }
        TraceCmd::Disable => {
            reporting::configure(home, None)?;
            reporting::status(home)
        }
        TraceCmd::Status => reporting::status(home),
        TraceCmd::Retry { api, background } => {
            let api = reporting::api(home, api.as_deref())?;
            reporting::Outbox::open(home, api)?
                .flush(if background { 100 } else { usize::MAX }, background)
                .map(|_| ())
        }
        TraceCmd::Push {
            trace,
            transcript,
            from,
            turn_id,
            thinking,
            api,
        } => {
            let queue = reporting::Outbox::open(home, reporting::api(home, api.as_deref())?)?;
            let (format, body) = if let Some(path) = trace {
                ("ecco-trace-v1", local::read(&path, 16 * 1024 * 1024)?)
            } else {
                let transcript = local::read(
                    &transcript.ok_or("--transcript is required")?,
                    16 * 1024 * 1024,
                )?;
                let mut body = json!({"agent":from.ok_or("--from is required")?, "transcript":transcript, "thinking":thinking});
                if let Some(turn) = turn_id {
                    body["turnId"] = json!(turn);
                }
                ("ecco-native-v1", body.to_string())
            };
            queue.enqueue(format, &body)?;
            queue
                .flush(100, false)
                .map(|_| ())
                .map_err(|e| format!("trace retained; retry with ecco traces retry: {e}"))
        }
    }
}
