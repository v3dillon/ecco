//! User service management for the native Ecco dispatcher.
use super::{config_path, Config, DispatcherCmd};
use crate::local;
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::Duration,
};
fn id(home: &Path) -> String {
    format!(
        "bot.ecco.dispatcher.{}",
        &local::sha256(home.to_string_lossy().as_bytes())[..16]
    )
}
fn unit(home: &Path) -> Result<PathBuf, String> {
    let user = local::home()?;
    if cfg!(target_os = "macos") {
        Ok(user
            .join("Library/LaunchAgents")
            .join(format!("{}.plist", id(home))))
    } else if cfg!(target_os = "linux") {
        Ok(std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| user.join(".config"))
            .join("systemd/user")
            .join(format!("{}.service", id(home))))
    } else {
        Err("dispatcher services support macOS and Linux".into())
    }
}
fn systemd(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}
fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn argv(home: &Path) -> Result<Vec<String>, String> {
    Ok(vec![
        std::env::current_exe()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned(),
        "--home".into(),
        home.to_string_lossy().into_owned(),
        "dispatcher".into(),
        "run".into(),
    ])
}
fn definition(home: &Path, cfg: &Config) -> Result<String, String> {
    let args = argv(home)?;
    let logs = home.join("dispatcher/logs");
    let env = cfg.handler.environment();

    if cfg!(target_os = "macos") {
        let label = xml(&id(home));
        let arguments = args
            .iter()
            .map(|s| format!("<string>{}</string>", xml(s)))
            .collect::<String>();
        let environment = env
            .iter()
            .map(|(k, v)| format!("<key>{}</key><string>{}</string>", xml(k), xml(v)))
            .collect::<String>();
        let work_dir = xml(&cfg.work_dir.to_string_lossy());
        let stdout = xml(&logs.join("stdout.log").to_string_lossy());
        let stderr = xml(&logs.join("stderr.log").to_string_lossy());
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array>{arguments}</array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>EnvironmentVariables</key><dict>{environment}</dict>
<key>WorkingDirectory</key><string>{work_dir}</string>
<key>StandardOutPath</key><string>{stdout}</string>
<key>StandardErrorPath</key><string>{stderr}</string>
</dict></plist>
"#
        ))
    } else {
        let environment = env
            .iter()
            .map(|(k, v)| format!("Environment={}\n", systemd(&format!("{k}={v}"))))
            .collect::<String>();
        let work_dir = systemd(&cfg.work_dir.to_string_lossy());
        let command = args
            .iter()
            .map(|s| systemd(&s.replace('$', "$$")))
            .collect::<Vec<_>>()
            .join(" ");
        let stdout = systemd(&logs.join("stdout.log").to_string_lossy());
        let stderr = systemd(&logs.join("stderr.log").to_string_lossy());
        Ok(format!(
            "[Unit]
Description=Ecco dispatcher

[Service]
Type=simple
{environment}WorkingDirectory={work_dir}
ExecStart={command}
Restart=on-failure
StandardOutput=append:{stdout}
StandardError=append:{stderr}

[Install]
WantedBy=default.target
"
        ))
    }
}

fn run(args: Vec<String>) -> Result<String, String> {
    local::process(
        &args,
        None,
        &local::home()?,
        &std::env::vars().collect(),
        Duration::from_secs(15),
        65536,
    )
}
fn systemctl(action: &str, home: Option<&Path>) -> Result<String, String> {
    let mut args = vec!["systemctl".into(), "--user".into(), action.into()];
    if let Some(home) = home {
        args.push(format!("{}.service", id(home)));
    }
    run(args)
}
fn launch(action: &str, home: &Path) -> Result<String, String> {
    let domain = format!("gui/{}", unsafe { libc::geteuid() });
    let path = unit(home)?.to_string_lossy().into_owned();
    let args = match action {
        "print" => vec![
            "launchctl".into(),
            "print".into(),
            format!("{domain}/{}", id(home)),
        ],
        "kickstart" => vec![
            "launchctl".into(),
            "kickstart".into(),
            "-k".into(),
            format!("{domain}/{}", id(home)),
        ],
        other => vec!["launchctl".into(), other.into(), domain, path],
    };
    run(args)
}
fn snapshot(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}
fn restore(path: &Path, previous: Option<Vec<u8>>) {
    if let Some(bytes) = previous {
        let _ = local::write(path, &bytes);
    } else {
        let _ = fs::remove_file(path);
    }
}
pub(super) fn install(home: &Path, cfg: &Config) -> Result<(), String> {
    let home = home.canonicalize().map_err(|e| e.to_string())?;
    let unit = unit(&home)?;
    let config = config_path(&home);
    let previous_unit = snapshot(&unit)?;
    let previous_config = snapshot(&config)?;
    let contacts_path = home.join("contacts.json");
    let previous_contacts = if contacts_path.exists() {
        Some(local::read(&contacts_path, 1024 * 1024)?)
    } else {
        None
    };
    let mut contacts: crate::identity::Contacts = previous_contacts
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("invalid contacts: {e}"))?
        .unwrap_or_default();
    for addr in &cfg.allow {
        contacts.insert(addr.clone(), "approved".into());
    }
    let active = if cfg!(target_os = "linux") && previous_unit.is_some() {
        systemctl("is-active", Some(&home)).is_ok()
    } else if cfg!(target_os = "macos") && previous_unit.is_some() {
        launch("print", &home).is_ok()
    } else {
        false
    };
    let enabled = cfg!(target_os = "linux") && systemctl("is-enabled", Some(&home)).is_ok();
    let definition = definition(&home, cfg)?;
    local::mkdir(&home.join("dispatcher/logs"))?;
    let result = (|| {
        local::write(
            &contacts_path,
            &serde_json::to_vec_pretty(&contacts).unwrap(),
        )?;
        local::write(&config, &serde_json::to_vec_pretty(cfg).unwrap())?;
        local::write(&unit, definition.as_bytes())?;
        if cfg!(target_os = "macos") {
            let _ = launch("bootout", &home);
            launch("bootstrap", &home)?;
            launch("kickstart", &home)?;
        } else {
            systemctl("daemon-reload", None)?;
            systemctl("enable", Some(&home))?;
            systemctl(if active { "restart" } else { "start" }, Some(&home))?;
        }
        Ok(())
    })();
    if result.is_err() {
        if cfg!(target_os = "macos") {
            let _ = launch("bootout", &home);
        } else {
            let _ = systemctl("stop", Some(&home));
            let _ = systemctl("disable", Some(&home));
        }
        restore(&contacts_path, previous_contacts.map(String::into_bytes));
        restore(&config, previous_config);
        restore(&unit, previous_unit);
        if cfg!(target_os = "macos") {
            if active {
                let _ = launch("bootstrap", &home);
            }
        } else {
            let _ = systemctl("daemon-reload", None);
            if enabled {
                let _ = systemctl("enable", Some(&home));
            }
            if active {
                let _ = systemctl("start", Some(&home));
            }
        }
    }
    result
}
pub(super) fn command(home: &Path, cmd: DispatcherCmd) -> Result<(), String> {
    let home = home.canonicalize().map_err(|e| e.to_string())?;
    let path = unit(&home)?;
    if matches!(cmd, DispatcherCmd::Status) && !path.exists() {
        println!("not installed; stopped");
        return Ok(());
    }
    match cmd {
        DispatcherCmd::Logs => {
            for name in ["stdout.log", "stderr.log"] {
                let path = home.join("dispatcher/logs").join(name);
                if path.exists() {
                    let mut file = fs::File::open(&path).map_err(|e| e.to_string())?;
                    let len = file.metadata().map_err(|e| e.to_string())?.len();
                    file.seek(SeekFrom::Start(len.saturating_sub(65536)))
                        .map_err(|e| e.to_string())?;
                    let mut bytes = Vec::new();
                    file.take(65536)
                        .read_to_end(&mut bytes)
                        .map_err(|e| e.to_string())?;
                    print!("{}", String::from_utf8_lossy(&bytes));
                }
            }
        }
        DispatcherCmd::Uninstall => {
            if cfg!(target_os = "macos") {
                if launch("print", &home).is_ok() {
                    launch("bootout", &home)?;
                }
            } else if path.exists() {
                systemctl("stop", Some(&home))?;
                systemctl("disable", Some(&home))?;
            }
            if path.exists() {
                fs::remove_file(path).map_err(|e| e.to_string())?;
            }
            if cfg!(target_os = "linux") {
                systemctl("daemon-reload", None)?;
            }
            println!("dispatcher service removed; queue and logs retained");
        }
        DispatcherCmd::Status => {
            let status = if cfg!(target_os = "macos") {
                launch("print", &home)
            } else {
                systemctl("is-active", Some(&home))
            };
            println!(
                "installed; {}",
                if status.is_ok() { "running" } else { "stopped" }
            );
        }
        DispatcherCmd::Start | DispatcherCmd::Restart | DispatcherCmd::Stop => {
            if !path.exists() {
                return Err("dispatcher is not installed".into());
            }
            if cfg!(target_os = "macos") {
                if matches!(cmd, DispatcherCmd::Stop) {
                    launch("bootout", &home)?;
                } else {
                    let _ = launch("bootstrap", &home);
                    launch("kickstart", &home)?;
                }
            } else {
                let action = match cmd {
                    DispatcherCmd::Start => "start",
                    DispatcherCmd::Restart => "restart",
                    _ => "stop",
                };
                systemctl(action, Some(&home))?;
            }
        }
        _ => return Err("unexpected service command".into()),
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_uses_core_with_an_explicit_home() {
        let home = Path::new("/tmp/identity with spaces");
        let cfg = Config {
            version: 1,
            allow: vec!["peer@relay".into()],
            work_dir: PathBuf::from("/tmp/repo"),
            handler: super::super::Handler {
                executable: "/bin/true".into(),
                args: vec![],
                env: vec![],
            },
            max_thread_requests: 8,
            thread_ttl_seconds: 3600,
        };
        let text = definition(home, &cfg).unwrap();
        assert!(text.contains("--home"));
        assert!(text.contains("identity with spaces"));
        assert!(!text.contains("ecco-ops"));
        assert!(text.contains("dispatcher"));
    }
}
