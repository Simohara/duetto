//! Local failure reports for the release application, which has no console.
//! Never record application settings, credentials, command arguments or audio.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn log_path(base: &Path) -> PathBuf {
    base.join("AirBridge-Rust").join("diagnostics.log")
}

/// Keep each report on one line and suppress messages that may contain secrets.
fn safe_message(message: &str) -> String {
    let lower = message.to_lowercase();
    let sensitive = [
        "credential",
        "password",
        "secret",
        "token",
        "private_key",
        "pin=",
        "pin:",
        "密码",
        "凭据",
        "口令",
    ]
    .iter()
    .any(|key| lower.contains(key));
    // Stored keys and encoded authentication material are long unbroken strings.
    let long_encoded_value = message
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || "_-/+=".contains(ch)))
        .any(|value| value.len() >= 48);
    if sensitive || long_encoded_value {
        return "[message omitted: possible authentication material]".into();
    }
    message
        .chars()
        .take(2048)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn append(kind: &str, location: Option<(&str, u32, u32)>, message: &str) {
    // Tests must never write to the user's real log.
    if cfg!(test) {
        return;
    }
    let Some(base) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let path = log_path(Path::new(&base));
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    // Bounded: one previous file is kept, so a long session cannot fill the disk.
    if fs::metadata(&path).is_ok_and(|meta| meta.len() > 1_048_576) {
        let _ = fs::rename(&path, path.with_extension("log.old"));
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let source = location
        .map(|(file, line, column)| format!(" at {file}:{line}:{column}"))
        .unwrap_or_default();
    let entry = format!(
        "unix={timestamp} pid={} {kind}{source}: {}\n",
        std::process::id(),
        safe_message(message)
    );
    // A failure to record a diagnostic must not cause another panic.
    let _ = file.write_all(entry.as_bytes());
}

pub fn record_error(message: &str) {
    append("error", None, message);
}

/// Writes `report` and the two logs, redacted again, into a folder of their
/// own: Explorer must never open the data folder with the credential files.
pub fn export(report: &str) -> Result<PathBuf, String> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or("缺少 LOCALAPPDATA")?;
    export_in(Path::new(&base), report).map_err(|e| e.to_string())
}

fn export_in(base: &Path, report: &str) -> io::Result<PathBuf> {
    let log = log_path(base);
    let dir = log.with_file_name("diagnostics-export");
    fs::create_dir_all(&dir)?;
    let mut text = format!("{report}\n");
    // A whitelist: nothing else in the data folder is ever read.
    for name in ["diagnostics.log.old", "diagnostics.log"] {
        text.push_str(&format!("\n--- {name} ---\n"));
        let Ok(file) = File::open(log.with_file_name(name)) else {
            text.push_str("(无)\n");
            continue;
        };
        let mut bytes = Vec::new();
        file.take(2 << 20).read_to_end(&mut bytes)?;
        // Logs from older builds may predate the redaction.
        for line in String::from_utf8_lossy(&bytes).lines() {
            text.push_str(&safe_message(line));
            text.push('\n');
        }
    }
    let path = dir.join("duetto-diagnostics.txt");
    fs::write(&path, text)?;
    Ok(path)
}

pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("non-string panic payload");
        append(
            "panic",
            info.location()
                .map(|where_| (where_.file(), where_.line(), where_.column())),
            message,
        );
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_path_stays_in_application_directory() {
        assert_eq!(
            log_path(Path::new(r"C:\Users\test\AppData\Local")),
            PathBuf::from(r"C:\Users\test\AppData\Local\AirBridge-Rust\diagnostics.log")
        );
    }
    #[test]
    fn export_redacts_whitelists_and_stays_in_app_dir() {
        let base = std::env::temp_dir().join(format!("airbridge-export-{}", std::process::id()));
        let data = base.join("AirBridge-Rust");
        fs::create_dir_all(&data).unwrap();
        let token = "A".repeat(60);
        fs::write(
            data.join("diagnostics.log"),
            format!("normal line\npassword: hunter2\nkey {token}\n"),
        )
        .unwrap();
        fs::write(data.join("192.0.2.1.7000.dpapi"), "DPAPI-MARKER").unwrap();
        let path = export_in(&base, "HEADER").unwrap();
        assert_eq!(
            path,
            data.join("diagnostics-export")
                .join("duetto-diagnostics.txt")
        );
        let text = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_dir_all(&base);
        assert!(text.starts_with("HEADER\n"));
        assert!(text.contains("--- diagnostics.log.old ---\n(无)\n"));
        assert!(text.contains("normal line"));
        assert!(!text.contains("hunter2"));
        assert!(!text.contains(&token));
        assert!(!text.contains("DPAPI-MARKER"));
    }
    #[test]
    fn panic_message_is_bounded_single_line_and_redacts_authentication_material() {
        assert_eq!(
            safe_message("called Option::unwrap()\nNone"),
            "called Option::unwrap() None"
        );
        assert_eq!(
            safe_message(&"x".repeat(49)),
            "[message omitted: possible authentication material]"
        );
        assert_eq!(
            safe_message("password: example"),
            "[message omitted: possible authentication material]"
        );
        assert_eq!(safe_message(&"界".repeat(2050)).chars().count(), 2048);
    }
}
