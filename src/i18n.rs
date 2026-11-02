//! Interface language. Messages are formatted in the language current when
//! they are made; the page translates its own text from the snapshot's `lang`.
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Lang {
    Zh,
    En,
    Ja,
}

/// Unset (tests, the CLI) means Chinese, the language the app was written in.
static LANG: AtomicU8 = AtomicU8::new(0);

pub fn lang() -> Lang {
    match LANG.load(Ordering::Relaxed) {
        1 => Lang::En,
        2 => Lang::Ja,
        _ => Lang::Zh,
    }
}

pub fn code(lang: Lang) -> &'static str {
    match lang {
        Lang::Zh => "zh",
        Lang::En => "en",
        Lang::Ja => "ja",
    }
}

/// `setting` is "zh", "en", "ja" or "system".
pub fn set(setting: &str) {
    let lang = resolve(setting, system_language());
    LANG.store(lang as u8, Ordering::Relaxed);
}

fn resolve(setting: &str, system: u16) -> Lang {
    match setting {
        "zh" => Lang::Zh,
        "en" => Lang::En,
        "ja" => Lang::Ja,
        // Windows primary language ids: 0x04 Chinese, 0x11 Japanese.
        _ => match system & 0x3ff {
            0x04 => Lang::Zh,
            0x11 => Lang::Ja,
            _ => Lang::En,
        },
    }
}

fn system_language() -> u16 {
    // Tests check Chinese messages whatever language the build machine runs.
    if cfg!(test) {
        return 0x0804;
    }
    unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() }
}

/// `tr!("中文 {x}", "English {x}", "日本語 {x}", args…)`: one `format!` per language.
macro_rules! tr {
    ($zh:literal, $en:literal, $ja:literal $(, $arg:expr)* $(,)?) => {
        match $crate::i18n::lang() {
            $crate::i18n::Lang::En => format!($en $(, $arg)*),
            $crate::i18n::Lang::Ja => format!($ja $(, $arg)*),
            $crate::i18n::Lang::Zh => format!($zh $(, $arg)*),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_language_picks_chinese_japanese_or_english() {
        assert_eq!(resolve("system", 0x0804), Lang::Zh);
        assert_eq!(resolve("system", 0x0404), Lang::Zh);
        assert_eq!(resolve("system", 0x0411), Lang::Ja);
        assert_eq!(resolve("system", 0x0409), Lang::En);
        assert_eq!(resolve("system", 0x0407), Lang::En);
        assert_eq!(resolve("ja", 0x0804), Lang::Ja);
        assert_eq!(resolve("en", 0x0411), Lang::En);
    }
}
