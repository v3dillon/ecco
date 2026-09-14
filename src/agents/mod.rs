//! Native hook installation. The catalog contains only agent-specific data;
//! identity selection, file updates and upload commands are shared.
use crate::local;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::OnceLock,
};
pub mod handler;

#[derive(Deserialize)]
pub struct Agent {
    pub name: String,
    pub label: String,
    pub command: String,
    env: String,
    dir: String,
    kind: String,
    path: String,
    event: String,
    files: BTreeMap<String, String>,
}
pub fn catalog() -> &'static [Agent] {
    static CATALOG: OnceLock<Vec<Agent>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("catalog.json")).expect("checked agent catalog")
    })
}
pub fn find(name: &str) -> Result<&'static Agent, String> {
    catalog()
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| format!("unknown agent {name}; run ecco agents"))
}
pub fn list(as_json: bool) {
    if as_json {
        println!(
            "{}",
            json!(catalog()
                .iter()
                .map(|a| json!({"name":a.name,"label":a.label}))
                .collect::<Vec<_>>())
        );
    } else {
        for a in catalog() {
            println!("{}\t{}", a.name, a.label);
        }
    }
}
const MARKER: &str = "managed by ecco";
const COMMAND_MARKER: &str = "# ecco managed trace";

fn root(agent: &Agent, user_home: &Path) -> PathBuf {
    if agent.name == "pi" {
        if let Some(path) = std::env::var_os("PI_CODING_AGENT_DIR") {
            return path.into();
        }
    }
    if let Some(path) = std::env::var_os(&agent.env) {
        return path.into();
    }
    if agent.name == "opencode" {
        if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
            return PathBuf::from(path).join("opencode");
        }
    }
    user_home.join(&agent.dir)
}
fn object(value: &mut Value) -> Result<&mut Map<String, Value>, String> {
    if value.is_null() {
        *value = json!({});
    }
    value
        .as_object_mut()
        .ok_or("expected a configuration object".into())
}
fn read_json(path: &Path) -> Result<Value, String> {
    if !path.exists() {
        return Ok(json!({}));
    }
    serde_json::from_str(&local::read(path, 1024 * 1024)?)
        .map_err(|e| format!("{}: {e}", path.display()))
}
fn owned(entry: &Value) -> bool {
    entry["command"]
        .as_str()
        .is_some_and(|s| s.ends_with(COMMAND_MARKER))
}
fn prune(hooks: &mut Map<String, Value>, event: &str, flat: bool) -> Result<(), String> {
    let Some(entries) = hooks.get_mut(event) else {
        return Ok(());
    };
    let entries = entries.as_array_mut().ok_or("expected a hook list")?;
    if flat {
        entries.retain(|e| !owned(e));
    } else {
        for entry in entries.iter_mut() {
            if let Some(group) = entry.get_mut("hooks").and_then(Value::as_array_mut) {
                group.retain(|e| !owned(e));
            }
        }
        entries.retain(|entry| !entry["hooks"].as_array().is_some_and(Vec::is_empty));
    }
    if entries.is_empty() {
        hooks.remove(event);
    }
    Ok(())
}
fn command(executable: &Path, home: &Path, api: &str, agent: &str) -> String {
    let args = [
        executable.to_string_lossy().into_owned(),
        "--home".into(),
        home.to_string_lossy().into_owned(),
        "traces".into(),
        "push".into(),
        "--from".into(),
        agent.into(),
        "--api".into(),
        api.into(),
    ];
    format!(
        "{} {COMMAND_MARKER}",
        args.iter()
            .map(|s| local::shell(s))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
fn substitute(content: &str, executable: &Path, home: &Path, api: &str) -> String {
    let mut text = content.to_string();
    for (marker, value) in [
        ("@@ecco@@", executable.to_string_lossy()),
        ("@@home@@", home.to_string_lossy()),
        ("@@api@@", api.into()),
    ] {
        let escaped = serde_json::to_string(value.as_ref()).unwrap();
        text = text.replace(marker, &escaped[1..escaped.len() - 1]);
    }
    text
}
fn managed_text(current: &str, command: Option<&str>) -> Result<String, String> {
    let begin = "# BEGIN managed by ecco";
    let end = "# END managed by ecco";
    let mut text = current.to_string();
    if let Some(start) = text.find(begin) {
        let stop = text[start..]
            .find(end)
            .ok_or("incomplete Ecco hook block")?
            + start
            + end.len();
        text.replace_range(start..stop, "");
    }
    if let Some(cmd) = command {
        text = format!(
            "{}\n\n{begin}\n[[hooks]]\nevent = \"SessionEnd\"\ncommand = {}\ntimeout = 60\n{end}\n",
            text.trim_end(),
            serde_json::to_string(cmd).unwrap()
        );
    }
    Ok(text)
}
fn hermes_config(current: &str, install: bool) -> Result<String, String> {
    let mut lines: Vec<String> = current.lines().map(str::to_string).collect();
    let start = lines.iter().position(|s| s == "plugins:");
    if start.is_none() {
        if !install {
            return Ok(current.into());
        }
        if lines.iter().any(|s| s.starts_with("plugins:")) {
            return Err("Hermes plugins config must use a YAML block".into());
        }
        return Ok(format!(
            "{}\nplugins:\n  enabled:\n    - ecco-trace\n",
            current.trim_end()
        ));
    }
    let start = start.unwrap();
    let stop = (start + 1..lines.len())
        .find(|&i| {
            !lines[i].starts_with(char::is_whitespace)
                && !lines[i].is_empty()
                && !lines[i].starts_with('#')
        })
        .unwrap_or(lines.len());
    let mut stop = stop;
    for i in (start + 1..stop).rev() {
        if lines[i].trim() == "- ecco-trace" {
            lines.remove(i);
            stop -= 1;
        }
    }
    if install {
        let enabled = (start + 1..stop).find(|&i| lines[i].trim() == "enabled:");
        if let Some(i) = enabled {
            lines.insert(i + 1, "    - ecco-trace".into());
        } else {
            lines.splice(
                start + 1..start + 1,
                ["  enabled:".into(), "    - ecco-trace".into()],
            );
        }
    }
    Ok(format!("{}\n", lines.join("\n")))
}
pub fn install(agent: &Agent, home: &Path, api: &str, remove: bool) -> Result<(), String> {
    install_at(
        agent,
        home,
        api,
        remove,
        &root(agent, &local::home()?),
        &std::env::current_exe().map_err(|e| e.to_string())?,
    )
}
fn install_at(
    agent: &Agent,
    home: &Path,
    api: &str,
    remove: bool,
    root: &Path,
    executable: &Path,
) -> Result<(), String> {
    let path = root.join(&agent.path);
    let cmd = command(executable, home, api, &agent.name);
    let mut writes = Vec::<(PathBuf, String)>::new();
    let mut deletes = Vec::new();
    for (relative, content) in &agent.files {
        let file = root.join(relative);
        if file.exists() && !local::read(&file, 1024 * 1024)?.contains(MARKER) {
            return Err(format!("{} is not managed by Ecco", file.display()));
        }
        if remove {
            deletes.push(file);
        } else {
            writes.push((file, substitute(content, executable, home, api)));
        }
    }
    if !agent.path.is_empty() && (!remove || path.exists()) {
        let text = match agent.kind.as_str() {
            "toml" | "hermes" => {
                let current = if path.exists() {
                    local::read(&path, 1024 * 1024)?
                } else {
                    String::new()
                };
                if agent.kind == "toml" {
                    managed_text(&current, if remove { None } else { Some(&cmd) })?
                } else {
                    hermes_config(&current, !remove)?
                }
            }
            _ => {
                let mut config = read_json(&path)?;
                let map = object(&mut config)?;
                if agent.kind == "openclaw" {
                    let plugins = object(map.entry("plugins").or_insert(json!({})))?;
                    let entries = object(plugins.entry("entries").or_insert(json!({})))?;
                    if remove {
                        entries.remove("ecco-trace");
                    } else {
                        entries.insert(
                            "ecco-trace".into(),
                            json!({"enabled":true,"hooks":{"allowConversationAccess":true}}),
                        );
                    }
                } else {
                    if agent.kind == "flat" {
                        map.insert("version".into(), json!(1));
                    }
                    let hooks = object(map.entry("hooks").or_insert(json!({})))?;
                    if agent.name == "codex" {
                        prune(hooks, "SessionEnd", false)?;
                    }
                    prune(hooks, &agent.event, agent.kind == "flat")?;
                    if !remove {
                        let entries = hooks
                            .entry(&agent.event)
                            .or_insert(json!([]))
                            .as_array_mut()
                            .ok_or("expected hook entries")?;
                        if agent.kind == "flat" {
                            entries.push(json!({"command":cmd}));
                        } else {
                            let mut entry = json!({"type":"command","command":cmd,"timeout":60});
                            if agent.event == "Stop" {
                                entry["async"] = json!(true);
                            }
                            entries.push(json!({"hooks":[entry]}));
                        }
                    }
                }
                format!("{}\n", serde_json::to_string_pretty(&config).unwrap())
            }
        };
        writes.push((path, text));
    }
    for (path, content) in writes {
        local::write(&path, content.as_bytes())?;
    }
    for path in deletes {
        if path.exists() {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        }
    }
    println!(
        "{}: {}{}",
        agent.label,
        if remove {
            "capture removed"
        } else {
            "capture configured"
        },
        if agent.name == "fx" {
            " (explicit share skill)"
        } else {
            ""
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hermes_merge_preserves_other_plugins_and_other_sections() {
        let before = "model: x\nplugins:\n  disabled: []\nother:\n  enabled:\n    - foreign\n";
        let after = hermes_config(before, true).unwrap();
        assert!(after.contains("plugins:\n  enabled:\n    - ecco-trace\n  disabled: []\n"));
        assert!(after.contains("other:\n  enabled:\n    - foreign\n"));
        assert_eq!(hermes_config(&after, true).unwrap(), after);
        assert!(!hermes_config(&after, false).unwrap().contains("ecco-trace"));
        assert!(hermes_config("plugins: {enabled: [foreign]}", true).is_err());
    }
    #[test]
    fn all_agent_hooks_call_only_core_and_preserve_identity() {
        let tmp = std::env::temp_dir().join(format!("ecco-hooks-{}", rand::random::<u64>()));
        local::mkdir(&tmp).unwrap();
        let home = tmp.join("identity with 'quotes'");
        let exe = Path::new("/bin/ecco with spaces");
        for agent in catalog() {
            let base = tmp.join(&agent.dir);
            install_at(agent, &home, "https://app.test", false, &base, exe).unwrap();
            install_at(agent, &home, "https://app.test", false, &base, exe).unwrap();
            for relative in agent.files.keys() {
                let text = fs::read_to_string(base.join(relative)).unwrap();
                assert!(!text.contains("ecco-ops"));
                if agent.files[relative].contains("@@home@@") {
                    assert!(text.contains("identity with"));
                    assert!(text.contains("traces"));
                }
            }
            if agent.kind == "group" || agent.kind == "flat" {
                let config = read_json(&base.join(&agent.path)).unwrap();
                assert_eq!(config["hooks"][&agent.event].as_array().unwrap().len(), 1);
                assert!(config.to_string().contains("traces"));
            }
            install_at(agent, &home, "https://app.test", true, &base, exe).unwrap();
        }
        fs::remove_dir_all(tmp).unwrap();
    }
}
