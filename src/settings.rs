use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Version marker: older builds treated master as receiver-volume percentage.
    pub linear_master: bool,
    pub master: u32,
    pub input: String,
    pub microphone: String,
    pub test_volume: u32,
    pub reconnect: bool,
    /// Whether `Duetto.exe --mcp` may drive the window.
    pub mcp: bool,
    /// Receiver playout buffer, 300-2000 ms.
    pub buffer_ms: u32,
    /// "light", "dark" or "system".
    pub theme: String,
    /// "zh", "en", "ja" or "system".
    pub language: String,
    pub routes: BTreeMap<String, SavedRoute>,
    /// Written by builds with stereo pairs; older files get the one-time
    /// left/right auto-pair migration.
    pub pairs: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            linear_master: false,
            master: 35,
            input: String::new(),
            microphone: String::new(),
            test_volume: 100,
            reconnect: false,
            mcp: true,
            buffer_ms: 2000,
            theme: "system".into(),
            language: "system".into(),
            routes: BTreeMap::new(),
            pairs: false,
        }
    }
}
impl Settings {
    pub fn playback_master(&self) -> u32 {
        // Legacy route.volume already contains the complete output level.
        // Do not attenuate it a second time when migrating to PCM master gain.
        if self.linear_master || self.master == 0 {
            self.master
        } else {
            100
        }
    }

    pub fn playback_route_volume(&self, route: &SavedRoute) -> u32 {
        if self.linear_master || self.master != 0 || route.volume != 0 {
            return route.volume;
        }
        // The old master mute overwrote every receiver volume with zero.
        // Reconstruct a quiet baseline from the retained relative offsets;
        // the PCM master stays muted until the user raises it again.
        let min = self.routes.values().map(|r| r.offset).min().unwrap_or(0);
        let max = self.routes.values().map(|r| r.offset).max().unwrap_or(0);
        let lower = 1 - min;
        let upper = 100 - max;
        let baseline = if lower <= upper {
            35.clamp(lower, upper)
        } else {
            35
        };
        (baseline + route.offset).clamp(1, 100) as u32
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn older_whole_millisecond_routes_still_load() {
        let settings: super::Settings =
            serde_json::from_str(r#"{"routes":{"192.0.2.209:7000":{"delay":25,"volume":50}}}"#)
                .unwrap();
        let route = &settings.routes["192.0.2.209:7000"];
        assert_eq!(
            (route.delay, route.trim, route.id.as_str()),
            (25.0, 0.0, "")
        );
    }
    #[test]
    fn legacy_settings_keep_existing_level_and_calibration() {
        let settings: super::Settings = serde_json::from_str(
            r#"{"master":40,"routes":{"192.0.2.209:7000":{"volume":30,"offset":-10}}}"#,
        )
        .unwrap();
        assert_eq!(settings.playback_master(), 100);
        assert_eq!(settings.routes["192.0.2.209:7000"].volume, 30);
        let muted: super::Settings = serde_json::from_str(r#"{"master":0}"#).unwrap();
        assert_eq!(muted.playback_master(), 0);
        let new: super::Settings =
            serde_json::from_str(r#"{"linear_master":true,"master":50}"#).unwrap();
        assert_eq!(new.playback_master(), 50);
    }

    #[test]
    fn legacy_master_mute_keeps_calibration_when_unmuted() {
        let settings: super::Settings = serde_json::from_str(
            r#"{"master":0,"routes":{"left":{"volume":0,"offset":-5},"right":{"volume":0,"offset":15}}}"#,
        )
        .unwrap();
        assert_eq!(settings.playback_master(), 0);
        assert_eq!(settings.playback_route_volume(&settings.routes["left"]), 30);
        assert_eq!(
            settings.playback_route_volume(&settings.routes["right"]),
            50
        );

        let current: super::Settings = serde_json::from_str(
            r#"{"linear_master":true,"master":0,"routes":{"left":{"volume":0}}}"#,
        )
        .unwrap();
        assert_eq!(current.playback_route_volume(&current.routes["left"]), 0);
    }

    #[test]
    fn out_of_range_values_are_repaired_instead_of_discarding_the_file() {
        assert!(super::parse(b"{not json").is_err());
        let (bom, repaired) = super::parse(b"\xEF\xBB\xBF{\"master\":40}").unwrap();
        assert_eq!((bom.master, repaired), (40, false));
        assert!(super::parse(&vec![b' '; 1_048_577]).is_err());
        let (settings, repaired) =
            super::parse(br#"{"master":150,"routes":{"192.0.2.1:7000":{"delay":12.5}}}"#).unwrap();
        assert!(repaired);
        assert_eq!(settings.master, 100);
        assert_eq!(settings.routes["192.0.2.1:7000"].delay, 12.5);
        let (settings, repaired) = super::parse(
            r#"{"routes":{"192.0.2.1:7000":{"delay":2500,"trim":-3.0,"partner":"192.0.2.2:7000","mode":7,"name":"NAME","home_pair":"A4"},"not-an-ip":{"delay":5}}}"#
                .replace("NAME", &"界".repeat(200))
                .as_bytes(),
        )
        .unwrap();
        let route = &settings.routes["192.0.2.1:7000"];
        assert!(repaired);
        assert_eq!(settings.routes.len(), 1);
        assert_eq!(
            (route.delay, route.trim, route.partner.as_str(), route.mode),
            (2000.0, -3.0, "192.0.2.2:7000", 0)
        );
        assert_eq!(route.name.len(), 510);
        assert_eq!(route.home_pair, "A4");
        let many: String = (1..=65)
            .map(|i| format!(r#""192.0.2.{i}:7000":{{"delay":1}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let (settings, repaired) =
            super::parse(format!(r#"{{"routes":{{{many}}}}}"#).as_bytes()).unwrap();
        assert_eq!((settings.routes.len(), repaired), (65, false));
        let (settings, _) = super::parse(b"{}").unwrap();
        assert!(!settings.pairs && settings.routes.is_empty());
    }

    #[test]
    fn unreadable_files_are_kept_aside_and_saves_leave_no_temp_file() {
        let dir = std::env::temp_dir().join(format!("airbridge-settings-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("settings.json");
        // A fresh install is not an error.
        assert!(matches!(super::load_from(&path), Ok(None)));
        let mut settings = super::Settings::default();
        settings.routes.insert(
            "192.0.2.1:7000".into(),
            super::SavedRoute {
                delay: 12.5,
                home_pair: "B71C0F3E".into(),
                ..Default::default()
            },
        );
        super::save_to(&path, &settings).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let (loaded, repaired) = super::load_from(&path).unwrap().unwrap();
        assert!(!repaired);
        assert_eq!(loaded.routes["192.0.2.1:7000"].home_pair, "B71C0F3E");
        // A repaired file keeps its original bytes in .bak.
        std::fs::write(&path, r#"{"master":150}"#).unwrap();
        assert!(super::load_from(&path).unwrap().unwrap().1);
        assert_eq!(
            std::fs::read_to_string(dir.join("settings.json.bak")).unwrap(),
            r#"{"master":150}"#
        );
        // A second bad file replaces only the previous .bad file.
        for bad in ["{one", "{two"] {
            std::fs::write(&path, bad).unwrap();
            assert!(matches!(super::load_from(&path), Err((_, false))));
            assert!(!path.exists());
            assert_eq!(
                std::fs::read_to_string(dir.join("settings.json.bad")).unwrap(),
                bad
            );
        }
        // A bad file that cannot be moved aside stays and blocks saving.
        std::fs::remove_file(dir.join("settings.json.bad")).unwrap();
        std::fs::create_dir(dir.join("settings.json.bad")).unwrap();
        std::fs::write(&path, "{three").unwrap();
        assert!(matches!(super::load_from(&path), Err((_, true))));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{three");
        // Reading a directory fails with something other than NotFound.
        assert!(matches!(super::load_from(&dir), Err((_, true))));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SavedRoute {
    pub name: String,
    pub enabled: bool,
    pub mode: u32,
    /// Milliseconds with 0.1 ms resolution; older files store whole numbers.
    pub delay: f64,
    pub volume: u32,
    pub offset: i32,
    /// Calibrated PCM level correction in dB, from -24 to 0.
    pub trim: f64,
    /// AirPlay TXT `deviceid`: follows the speaker when its IP address changes.
    pub id: String,
    /// The other half of this speaker's stereo pair (its route address).
    pub partner: String,
    /// TXT `tsid` from the last scan: members of one Home stereo pair share it.
    pub home_pair: String,
}
fn path() -> Option<PathBuf> {
    Some(
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?)
            .join("AirBridge-Rust")
            .join("settings.json"),
    )
}
/// Out-of-range values are repaired in place; the flag is true when any
/// were. Only a route whose address is unusable is dropped.
fn parse(data: &[u8]) -> Result<(Settings, bool), String> {
    if data.len() > 1_048_576 {
        return Err(tr!(
            "设置文件超过 1 MB",
            "The settings file is larger than 1 MB",
            "設定ファイルが 1 MB を超えています"
        ));
    }
    // Notepad saves UTF-8 with a BOM, which serde_json rejects.
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let mut settings: Settings = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    let before = serde_json::to_string(&settings).map_err(|e| e.to_string())?;
    settings.master = settings.master.min(100);
    settings.test_volume = settings.test_volume.min(100);
    settings.buffer_ms = settings.buffer_ms.clamp(300, 2000);
    if !matches!(settings.theme.as_str(), "light" | "dark" | "system") {
        settings.theme = "system".into();
    }
    if !matches!(settings.language.as_str(), "zh" | "en" | "ja" | "system") {
        settings.language = "system".into();
    }
    settings
        .routes
        .retain(|addr, _| crate::host_port(addr).is_ok());
    for r in settings.routes.values_mut() {
        if r.name.len() >= 512 {
            let mut end = 511;
            while !r.name.is_char_boundary(end) {
                end -= 1;
            }
            r.name.truncate(end);
        }
        if r.mode > 3 {
            r.mode = 0;
        }
        r.delay = r.delay.clamp(0.0, 2000.0);
        r.trim = r.trim.clamp(-24.0, 0.0);
        r.volume = r.volume.min(100);
        r.offset = r.offset.clamp(-100, 100);
        if r.id.len() >= 64 {
            r.id.clear();
        }
        if r.home_pair.len() >= 64 {
            r.home_pair.clear();
        }
        if !r.partner.is_empty() && crate::host_port(&r.partner).is_err() {
            r.partner.clear();
        }
    }
    let repaired = serde_json::to_string(&settings).map_err(|e| e.to_string())? != before;
    Ok((settings, repaired))
}
/// `Err((message, block_saving))`: saving stays blocked when the unreadable
/// file could not be moved aside, so it is never replaced by defaults.
pub fn load() -> Result<Option<Settings>, (String, bool)> {
    let Some(path) = path() else {
        return Ok(None);
    };
    Ok(load_from(&path)?.map(|(settings, repaired)| {
        if repaired {
            crate::diagnostics::record_error("设置中有无效项已修正");
        }
        settings
    }))
}
fn load_from(path: &Path) -> Result<Option<(Settings, bool)>, (String, bool)> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err((e.to_string(), true)),
    };
    match parse(&data) {
        Ok((settings, repaired)) => {
            if repaired {
                // Best effort: the original bytes stay beside the repaired file.
                let _ = fs::copy(path, path.with_extension("json.bak"));
            }
            Ok(Some((settings, repaired)))
        }
        Err(error) => {
            // Replaces an older .bad file; only the latest bad file is kept.
            let blocked = fs::rename(path, path.with_extension("json.bad")).is_err();
            Err((error, blocked))
        }
    }
}
pub fn save(settings: &Settings) -> Result<(), String> {
    save_to(&path().ok_or("缺少 LOCALAPPDATA")?, settings)
}
fn save_to(path: &Path, settings: &Settings) -> Result<(), String> {
    fs::create_dir_all(path.parent().ok_or_else(|| {
        tr!(
            "设置目录无效",
            "Invalid settings folder",
            "設定フォルダーが無効です"
        )
    })?)
    .map_err(|e| e.to_string())?;
    let data = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    // Flushed before the rename, so a power loss cannot leave an empty file.
    let write = (|| {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(&data)?;
        file.sync_all()
    })();
    if let Err(e) = write {
        let _ = fs::remove_file(&tmp);
        return Err(e.to_string());
    }
    use std::os::windows::ffi::OsStrExt;
    let from: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let success = unsafe {
        windows_sys::Win32::Storage::FileSystem::MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING
                | windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH,
        )
    };
    if success == 0 {
        let _ = fs::remove_file(tmp);
        return Err(tr!(
            "无法保存设置",
            "Cannot save the settings",
            "設定を保存できません"
        ));
    }
    Ok(())
}
