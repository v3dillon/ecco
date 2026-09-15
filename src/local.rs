//! Small local-runtime primitives: private atomic files, bounded reads, and a
//! bounded child process. No shell interpretation of agent input.
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt},
    process::CommandExt,
};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

static CANCELLED: AtomicBool = AtomicBool::new(false);
pub fn cancelled() -> bool {
    CANCELLED.load(Ordering::Relaxed)
}
extern "C" fn cancel(_: libc::c_int) {
    CANCELLED.store(true, Ordering::Relaxed);
}
pub fn install_signals() {
    unsafe {
        libc::signal(libc::SIGINT, cancel as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, cancel as *const () as libc::sighandler_t);
    }
}

/// Atomic private write: temp file with mode 0600, fsync, rename.
pub fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("file needs a parent directory")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temporary = parent.join(format!(
        ".ecco-{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&temporary, path).map_err(|e| e.to_string())?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())
    })();
    let _ = fs::remove_file(&temporary);
    result
}

/// Bounded read of a regular file; symlinks and special files are refused.
pub fn read(path: &Path, maximum: usize) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("expected a regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > maximum {
        return Err(format!("{} exceeds {maximum} bytes", path.display()));
    }
    String::from_utf8(bytes).map_err(|_| "file is not UTF-8".into())
}

/// An executable this user may safely run: a regular file, executable, not
/// writable by group or others, owned by root or the current user.
pub fn executable(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let info = fs::metadata(&path).map_err(|e| e.to_string())?;
    let uid = unsafe { libc::geteuid() };
    if !info.is_file()
        || info.mode() & 0o111 == 0
        || info.mode() & 0o022 != 0
        || (info.uid() != 0 && info.uid() != uid)
    {
        return Err(format!("unsafe executable: {}", path.display()));
    }
    Ok(path)
}

pub fn environment(keys: &[String]) -> BTreeMap<String, String> {
    keys.iter()
        .filter_map(|key| std::env::var(key).ok().map(|v| (key.clone(), v)))
        .collect()
}

/// Run a child with a clean environment, bounded output, and a deadline. The
/// child gets its own session so its whole process group can be killed.
pub fn process(
    argv: &[String],
    input: Option<&str>,
    cwd: &Path,
    env: &BTreeMap<String, String>,
    timeout: Duration,
    maximum: usize,
) -> Result<String, String> {
    let mut command = Command::new(argv.first().ok_or("empty command")?);
    command
        .args(&argv[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let pid = child.id() as libc::pid_t;
    let input = input.unwrap_or("").as_bytes().to_vec();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let exceeded = Arc::new(AtomicBool::new(false));
    let drain = |mut stream: Box<dyn Read + Send>| {
        let exceeded = Arc::clone(&exceeded);
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut block = [0; 4096];
            while let Ok(n) = stream.read(&mut block) {
                if n == 0 {
                    break;
                }
                if out.len() + n > maximum {
                    exceeded.store(true, Ordering::SeqCst);
                    break;
                }
                out.extend_from_slice(&block[..n]);
            }
            out
        })
    };
    let stdout = drain(Box::new(child.stdout.take().unwrap()));
    let stderr = drain(Box::new(child.stderr.take().unwrap()));
    let start = Instant::now();
    let outcome = loop {
        if cancelled() {
            break Err("dispatcher stopped".into());
        }
        if exceeded.load(Ordering::SeqCst) {
            break Err("handler output exceeded limit".into());
        }
        if start.elapsed() >= timeout {
            break Err("handler command timed out".into());
        }
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => break Err(e.to_string()),
        }
    };
    // Close inherited pipes as well as the direct child; no detached handler work.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.wait();
    let _ = writer.join();
    let out = stdout.join().map_err(|_| "stdout reader failed")?;
    let err = stderr.join().map_err(|_| "stderr reader failed")?;
    let status = outcome?;
    if !status.success() {
        return Err(format!(
            "handler exited {status}: {}",
            String::from_utf8_lossy(&err)
        ));
    }
    if exceeded.load(Ordering::SeqCst) {
        return Err("handler output exceeded limit".into());
    }
    String::from_utf8(out).map_err(|_| "handler output is not UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_bounds_output_time_and_inherited_pipes() {
        let env = BTreeMap::new();
        let run = |script: &str, timeout, maximum| {
            process(
                &["/bin/sh".into(), "-c".into(), script.into()],
                None,
                Path::new("/tmp"),
                &env,
                timeout,
                maximum,
            )
        };
        assert_eq!(run("printf ok", Duration::from_secs(1), 32).unwrap(), "ok");
        assert!(run("printf 123456789", Duration::from_secs(1), 4).is_err());
        assert!(run("exit 3", Duration::from_secs(1), 32).is_err());
        let start = Instant::now();
        assert!(run("sleep 5", Duration::from_millis(100), 32)
            .unwrap_err()
            .contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(2));
        let start = Instant::now();
        assert_eq!(
            run("sleep 5 & printf ok", Duration::from_secs(1), 32).unwrap(),
            "ok"
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn files_are_private_bounded_and_reject_symlinks() {
        let root = std::env::temp_dir().join(format!("ecco-local-{}", rand::random::<u64>()));
        let path = root.join("data");
        write(&path, b"test").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(read(&path, 4).unwrap(), "test");
        assert!(read(&path, 3).is_err());
        std::os::unix::fs::symlink(&path, root.join("link")).unwrap();
        assert!(read(&root.join("link"), 4).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
