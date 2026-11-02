use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=assets/airbridge.ico");
    println!("cargo:rerun-if-changed=assets/airbridge.rc");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc")
    {
        return;
    }

    let Some(rc) = find_rc() else {
        println!(
            "cargo:warning=Windows SDK rc.exe not found; the window icon is still configured at runtime, but this build will not have an Explorer icon resource."
        );
        return;
    };

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let assets = manifest.join("assets");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("out dir")).join("airbridge.res");
    let result = Command::new(&rc)
        .current_dir(&assets)
        .arg("/nologo")
        .arg(format!("/fo{}", output.display()))
        .arg("airbridge.rc")
        .status();

    match result {
        Ok(status) if status.success() => {
            println!(
                "cargo:rustc-link-arg-bin=airbridge-rust={}",
                output.display()
            );
        }
        Ok(status) => panic!("Windows resource compiler failed with {status}"),
        Err(error) => panic!("failed to run {}: {error}", rc.display()),
    }
}

fn find_rc() -> Option<PathBuf> {
    if let Some(path) = env::var_os("PATH") {
        for directory in env::split_paths(&path) {
            let candidate = directory.join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    let root = env::var_os("WindowsSdkDir")
        .map(PathBuf::from)
        .or_else(|| {
            Some(PathBuf::from(r"C:\Program Files (x86)\Windows Kits\10\bin"))
                .filter(|path| path.is_dir())
        })?;
    let mut versions: Vec<_> = std::fs::read_dir(root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    versions.sort();
    versions.reverse();
    versions
        .into_iter()
        .map(|version| version.join("x64").join("rc.exe"))
        .find(|candidate| candidate.is_file())
}
