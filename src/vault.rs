use cidermill_airplay::pairing::HapCredentials;
use std::{
    collections::HashMap,
    error::Error,
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPT_STRING_BASE64, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
        CryptStringToBinaryA, CryptUnprotectData,
    },
};

fn protected(data: &[u8], decrypt: bool) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| {
            io::Error::other(tr!(
                "凭据过大",
                "Credential too large",
                "認証情報が大きすぎます"
            ))
        })?,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        if decrypt {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}
fn filename(target: &str) -> Result<PathBuf, Box<dyn Error>> {
    let address: SocketAddr = if target.contains(':') {
        target.parse()?
    } else {
        format!("{target}:7000").parse()?
    };
    if !address.is_ipv4() {
        return Err(tr!(
            "当前仅支持 IPv4 配对地址",
            "Only IPv4 pairing addresses are supported",
            "ペアリングは IPv4 アドレスのみ対応しています"
        )
        .into());
    }
    let root = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("缺少 LOCALAPPDATA")?)
        .join("AirBridge-Rust");
    Ok(root.join(format!("{}.{}.dpapi", address.ip(), address.port())))
}
pub fn load(target: &str) -> Result<Option<String>, Box<dyn Error>> {
    let path = filename(target)?;
    match fs::read(path) {
        Ok(data) => Ok(Some(String::from_utf8(protected(&data, true)?)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
/// Moves pairing credentials with their speaker when its address changes;
/// whatever was stored for the other address moves the opposite way.
pub fn swap(a: &str, b: &str) -> Result<(), Box<dyn Error>> {
    swap_paths(&filename(a)?, &filename(b)?)
}
fn swap_paths(a: &Path, b: &Path) -> Result<(), Box<dyn Error>> {
    if a == b {
        return Ok(());
    }
    let parked = a.with_extension("dpapi.swap");
    // A swap interrupted after parking `a` left its credential only here; it
    // is undone first. Interrupted after moving `b` to `a`, that goes back too.
    if parked.exists() && a.exists() && !b.exists() {
        fs::rename(a, b)?;
    }
    if parked.exists() && !a.exists() {
        fs::rename(&parked, a)?;
    }
    match (a.exists(), b.exists()) {
        (false, false) => {}
        (true, false) => fs::rename(a, b)?,
        (false, true) => fs::rename(b, a)?,
        (true, true) => {
            if parked.exists() {
                return Err(tr!(
                    "存在未完成的凭据交换文件，未覆盖",
                    "An unfinished credential swap file exists; nothing was overwritten",
                    "入れ替え途中の認証情報ファイルがあるため、上書きしていません"
                )
                .into());
            }
            fs::rename(a, &parked)?;
            if let Err(error) = fs::rename(b, a) {
                // Restore rather than leave the first credential under a temporary name.
                let _ = fs::rename(&parked, a);
                return Err(error.into());
            }
            if let Err(error) = fs::rename(&parked, b) {
                let _ = fs::rename(a, b);
                let _ = fs::rename(&parked, a);
                return Err(error.into());
            }
        }
    }
    Ok(())
}
/// Whether a credential file exists; not decrypted, so an unreadable one can
/// still be replaced by re-pairing.
pub fn exists(target: &str) -> bool {
    filename(target).is_ok_and(|p| p.exists())
}
/// `replace` overwrites an existing credential, and only once the new one is
/// fully on disk; otherwise an existing file is never touched.
pub fn save(target: &str, text: &str, replace: bool) -> Result<(), Box<dyn Error>> {
    let path = filename(target)?;
    fs::create_dir_all(path.parent().ok_or_else(|| {
        tr!(
            "配置目录无效",
            "Invalid data folder",
            "データフォルダーが無効です"
        )
    })?)?;
    let data = protected(text.as_bytes(), false)?;
    Ok(write_path(&path, &data, replace)?)
}
fn write_path(path: &Path, data: &[u8], replace: bool) -> io::Result<()> {
    use std::io::Write;
    if !replace {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        if let Err(error) = file.write_all(data).and_then(|_| file.sync_all()) {
            drop(file);
            // Created by this call (create_new), so no earlier credential is lost.
            let _ = fs::remove_file(path);
            return Err(error);
        }
        return Ok(());
    }
    let tmp = path.with_extension("dpapi.new");
    let written = fs::File::create(&tmp)
        .and_then(|mut file| file.write_all(data).and_then(|_| file.sync_all()))
        .and_then(|_| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}
/// Copies PIN-pairing credentials from the Python version, only when asked:
/// its file is only read, and an existing credential is never overwritten.
/// `rows` are (address, TXT deviceid) of known speakers; returns how many
/// were imported and skipped. Errors never carry the file's contents.
pub fn import_python(rows: &[(String, String)]) -> Result<(usize, usize), String> {
    use std::io::Read;
    let root = std::env::var_os("LOCALAPPDATA").ok_or("缺少 LOCALAPPDATA")?;
    let path = PathBuf::from(root)
        .join("AirBridge")
        .join("credentials.dpapi.json");
    let mut envelope = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(PYTHON_LIMIT + 1).read_to_end(&mut envelope))
        .map_err(|_| {
            tr!(
                "未找到旧版凭据文件",
                "No credential file from the old version was found",
                "旧バージョンの認証情報ファイルが見つかりません"
            )
        })?;
    if envelope.len() as u64 > PYTHON_LIMIT {
        return Err(unreadable());
    }
    let entries =
        serde_json::from_slice(&python_plaintext(&envelope)?).map_err(|_| unreadable())?;
    let (found, mut skipped) = python_matches(&entries, rows, &exists);
    let mut imported = 0;
    for (address, credential) in found {
        if save(&address, &credential, false).is_ok() {
            imported += 1;
        } else {
            skipped += 1;
        }
    }
    Ok((imported, skipped))
}
/// The Python version refuses larger vault files too.
const PYTHON_LIMIT: u64 = 8 << 20;
fn unreadable() -> String {
    tr!(
        "旧版凭据无法读取（需用创建它的 Windows 账户）",
        "The old credentials cannot be read (use the Windows account that created them)",
        "旧バージョンの認証情報を読み取れません（作成した Windows アカウントで実行してください）"
    )
}
/// The Python vault file is {"version":1,"dpapi":base64(DPAPI(json))}.
fn python_plaintext(envelope: &[u8]) -> Result<Vec<u8>, String> {
    let value: serde_json::Value = serde_json::from_slice(envelope).map_err(|_| unreadable())?;
    let (Some(1), Some(text)) = (value["version"].as_u64(), value["dpapi"].as_str()) else {
        return Err(unreadable());
    };
    protected(&base64(text).ok_or_else(unreadable)?, true).map_err(|_| unreadable())
}
fn base64(text: &str) -> Option<Vec<u8>> {
    // A zero length would make the API read up to a NUL terminator.
    let length = u32::try_from(text.len()).ok().filter(|&n| n > 0)?;
    let decode = |out: *mut u8, size: &mut u32| unsafe {
        CryptStringToBinaryA(
            text.as_ptr(),
            length,
            CRYPT_STRING_BASE64,
            out,
            size,
            ptr::null_mut(),
            ptr::null_mut(),
        ) != 0
    };
    let mut size = 0u32;
    if !decode(ptr::null_mut(), &mut size) {
        return None;
    }
    let mut out = vec![0u8; size as usize];
    decode(out.as_mut_ptr(), &mut size).then(|| {
        out.truncate(size as usize);
        out
    })
}
/// Python keys are the RAOP name prefix (hex MAC), ours the TXT deviceid
/// (`AA:BB:..`); group ids and IP fallback keys never match. Only complete
/// HAP credentials are taken, and never for an address that has one.
fn python_matches(
    entries: &HashMap<String, serde_json::Value>,
    rows: &[(String, String)],
    exists: &dyn Fn(&str) -> bool,
) -> (Vec<(String, String)>, usize) {
    let normal = |id: &str| {
        Some(id.replace(':', "").to_ascii_uppercase())
            .filter(|id| id.len() == 12 && id.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    let (mut found, mut skipped) = (Vec::new(), 0);
    for (address, id) in rows {
        let Some(id) = normal(id) else { continue };
        let Some(credential) = entries
            .iter()
            .find(|(key, _)| normal(key).as_ref() == Some(&id))
            .and_then(|(_, entry)| entry["credentials"].as_str())
        else {
            continue;
        };
        if exists(address) || HapCredentials::parse(credential).is_err() {
            skipped += 1;
        } else {
            found.push((address.clone(), credential.trim().to_owned()));
        }
    }
    (found, skipped)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_follow_their_speaker() {
        let dir = std::env::temp_dir().join(format!("airbridge-vault-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a.dpapi"), dir.join("b.dpapi"));
        fs::write(&a, "A").unwrap();
        swap_paths(&a, &b).unwrap();
        assert!(!a.exists());
        assert_eq!(fs::read_to_string(&b).unwrap(), "A");
        fs::write(&a, "B").unwrap();
        swap_paths(&a, &b).unwrap();
        assert_eq!(fs::read_to_string(&a).unwrap(), "A");
        assert_eq!(fs::read_to_string(&b).unwrap(), "B");
        swap_paths(&a, &a).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn interrupted_swap_recovers_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("airbridge-swap-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let (a, b) = (dir.join("a.dpapi"), dir.join("b.dpapi"));
        let parked = a.with_extension("dpapi.swap");
        // Interrupted after parking A: A comes back, then moves to b.
        fs::write(&parked, "A").unwrap();
        fs::write(&b, "B").unwrap();
        swap_paths(&a, &b).unwrap();
        assert!(!parked.exists());
        assert_eq!(fs::read_to_string(&a).unwrap(), "B");
        assert_eq!(fs::read_to_string(&b).unwrap(), "A");
        // A stray parked file beside two credentials is not overwritten.
        fs::write(&parked, "P").unwrap();
        assert!(swap_paths(&a, &b).is_err());
        assert_eq!(fs::read_to_string(&parked).unwrap(), "P");
        assert_eq!(fs::read_to_string(&a).unwrap(), "B");
        assert_eq!(fs::read_to_string(&b).unwrap(), "A");
        // Interrupted after moving B to a: undone, then swapped.
        fs::remove_file(&b).unwrap();
        fs::write(&parked, "A").unwrap();
        swap_paths(&a, &b).unwrap();
        assert!(!parked.exists());
        assert_eq!(fs::read_to_string(&a).unwrap(), "B");
        assert_eq!(fs::read_to_string(&b).unwrap(), "A");
        fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn replace_only_when_asked() {
        let dir = std::env::temp_dir().join(format!("airbridge-write-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.dpapi");
        write_path(&path, b"old", false).unwrap();
        assert!(write_path(&path, b"new", false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"old");
        write_path(&path, b"new", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert!(!path.with_extension("dpapi.new").exists());
        let fresh = dir.join("b.dpapi");
        write_path(&fresh, b"first", true).unwrap();
        assert_eq!(fs::read(&fresh).unwrap(), b"first");
        fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn python_credentials_match_by_deviceid_only() {
        let hap = format!("{}:{}:3344:5566", "11".repeat(32), "22".repeat(32));
        assert_eq!(
            HapCredentials::parse(&hap).unwrap().to_storage_string(),
            hap
        );
        let entries: HashMap<String, serde_json::Value> =
            serde_json::from_value(serde_json::json!({
                "aabbccddee01": { "credentials": hap, "password": "secret" },
                "AABBCCDDEE02": { "credentials": "aa:bb" },
                "AABBCCDDEE03": { "password": "secret" },
                "group:1234": { "credentials": hap },
                "AABBCCDDEE04": { "credentials": hap },
                "192.168.1.9": { "credentials": hap },
            }))
            .unwrap();
        let rows: Vec<(String, String)> = [
            ("10.0.0.1:7000", "AA:BB:CC:DD:EE:01"),
            ("10.0.0.2:7000", "AA:BB:CC:DD:EE:02"),
            ("10.0.0.3:7000", "AA:BB:CC:DD:EE:03"),
            ("10.0.0.4:7000", "AA:BB:CC:DD:EE:04"),
            ("10.0.0.5:7000", "group:1234"),
            ("192.168.1.9:7000", "192.168.1.9"),
        ]
        .iter()
        .map(|(a, id)| (a.to_string(), id.to_string()))
        .collect();
        let (found, skipped) = python_matches(&entries, &rows, &|a| a == "10.0.0.4:7000");
        assert_eq!(found, vec![("10.0.0.1:7000".to_string(), hap.clone())]);
        // The legacy 2-field credential, and the address that already has one.
        assert_eq!(skipped, 2);
    }
    #[test]
    fn python_envelope_errors_carry_no_secret() {
        for envelope in [
            r#"{"version":2,"dpapi":"c2VjcmV0"}"#,
            r#"{"version":1,"dpapi":7}"#,
            r#"{"version":1,"dpapi":""}"#,
            "secret",
        ] {
            assert_eq!(python_plaintext(envelope.as_bytes()), Err(unreadable()));
        }
        assert_eq!(base64("c2VjcmV0").unwrap(), b"secret");
        assert_eq!(base64("!!"), None);
    }
    #[test]
    fn dpapi_roundtrip() {
        let secret = b"test-secret";
        let ciphertext = protected(secret, false).unwrap();
        assert_ne!(ciphertext, secret);
        assert_eq!(protected(&ciphertext, true).unwrap(), secret);
    }
}
