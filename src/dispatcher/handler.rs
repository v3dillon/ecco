//! The handler boundary: `ecco-dispatch-v1` JSON on stdin, one result on
//! stdout. Adapters own agent launch, credentials, and permissions.
use crate::local;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, time::Duration};

/// Result text limit; the process output limit leaves room for JSON framing.
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// Environment always passed through; `--handler-env` adds to it.
const INHERITED_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Handler {
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
}
impl Handler {
    pub fn validate(&self) -> Result<(), String> {
        if !Path::new(&self.executable).is_absolute() {
            return Err("--handler must be absolute".into());
        }
        local::executable(&self.executable)?;
        for key in &self.env {
            if key.is_empty()
                || !key.bytes().enumerate().all(|(i, c)| {
                    c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                })
            {
                return Err("--handler-env requires an environment variable name".into());
            }
        }
        Ok(())
    }
    fn environment(&self) -> BTreeMap<String, String> {
        let mut keys: Vec<String> = INHERITED_ENV.iter().map(|s| s.to_string()).collect();
        keys.extend(self.env.clone());
        local::environment(&keys)
    }
    pub fn run(
        &self,
        cwd: &Path,
        input: &Value,
        timeout: Duration,
    ) -> Result<ResultMessage, String> {
        let output = local::process(
            &[vec![self.executable.clone()], self.args.clone()].concat(),
            Some(&input.to_string()),
            cwd,
            &self.environment(),
            timeout,
            MAX_OUTPUT_BYTES,
        )?;
        ResultMessage::decode(serde_json::from_str(&output).map_err(|e| e.to_string())?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultMessage {
    pub kind: String,
    pub text: String,
    pub follow_up: Option<String>,
}
impl ResultMessage {
    pub fn decode(value: Value) -> Result<Self, String> {
        let result: Self = serde_json::from_value(value).map_err(|e| e.to_string())?;
        let usable = |s: &str| !s.trim().is_empty() && s.len() <= MAX_TEXT_BYTES;
        if !["finding", "proposal"].contains(&result.kind.as_str())
            || !usable(&result.text)
            || result.follow_up.as_deref().is_some_and(|s| !usable(s))
            || (result.kind == "proposal" && result.follow_up.is_some())
        {
            return Err("invalid dispatcher result".into());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn rejects_authority_escalation_and_invalid_results() {
        for value in [
            json!({"kind":"decision","text":"approved"}),
            json!({"kind":"finding","text":" "}),
            json!({"kind":"proposal","text":"approve?","follow_up":"run it"}),
            json!({"kind":"finding","text":"ok","command":"rm"}),
        ] {
            assert!(ResultMessage::decode(value).is_err());
        }
        assert!(ResultMessage::decode(json!({"kind":"finding","text":"ok"})).is_ok());
        assert!(ResultMessage::decode(json!({"kind":"proposal","text":"approve?"})).is_ok());
    }
}
