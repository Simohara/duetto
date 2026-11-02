# Duetto

English · [中文](README.zh-CN.md)

Duetto streams Windows audio to AirPlay 2 speakers such as the HomePod. Two speakers can play as a left/right stereo pair, and a microphone calibrates their arrival time and loudness. It is a native Rust app that ships as a single EXE and needs no Python.

The interface is in Chinese.

## Interface

### Speakers

![Speakers page, light theme](docs/screenshots/speakers-light.png)

- **Route map.** Audio flows from CABLE Output to each speaker. A stereo pair's line splits into a blue (left) and an orange (right) branch, and signal moves along the lines while playing.
- **Stereo pair card.** A pair shows as one card, and its two speakers are selected and played together. The pair can be swapped or split.
  - Each speaker has its own delay, level trim and volume.
  - Each speaker also shows its estimated output level.
- **Home app hint.** When the Home app already pairs two speakers, a banner offers to pair them here with one click.

![Speakers page, dark theme, playing](docs/screenshots/speakers-dark.png)

While playing, the input level and dropped packet count appear next to the input source, and the sidebar shows the run state.

### Calibration

![Calibration page](docs/screenshots/calibrate-dark.png)

- Place a microphone at the listening position, start the continuous test, then press 测量并调平 ("measure and level").
- In about 20 seconds Duetto measures how much later and louder the right side arrives than the left, and applies the correction immediately.
- The marker at the top shows where the stereo image sits. It returns to the centre once the pair is aligned.

### Settings

![Settings page](docs/screenshots/settings-light.png)

The Settings page holds:

- the theme (light, dark or follow system);
- the playback buffer (300–2000 ms);
- automatic reconnect;
- importing credentials from the old Python version;
- exporting diagnostics.

Changes save automatically after about a second.

## Requirements

- Windows 10 or 11 with the WebView2 runtime, which is built into Windows 11.
- The [VB-CABLE](https://vb-audio.com/Cable/) virtual audio device. Set the playing app's output to **CABLE Input**; Duetto captures from **CABLE Output**.
- AirPlay 2 speakers on the same local network.

## Usage

1. Run `airbridge-rust.exe` and press 扫描音响 ("scan") on the Speakers page. If a speaker is not found, enter its IP at the bottom of the page.
2. Tick the speakers. To use two of them as left and right, press 组成立体声对 ("make stereo pair").
3. The first connection needs pairing. On the speaker, press 测试目标 ("test target"), then PIN 配对 ("PIN pairing"), and enter the 4-digit PIN the speaker shows.
4. Press 开始桥接 ("start bridging") in the sidebar. The master volume scales all audio without touching any speaker's calibration.
5. To calibrate, tick a single stereo pair. Once bridging has run for 30 seconds, measure on the Calibration page, and measure again to verify.

## Data

All data lives in `%LOCALAPPDATA%\AirBridge-Rust`:

- `settings.json` holds the settings.
- `*.dpapi` files hold the pairing credentials, encrypted with DPAPI for the current Windows user.
- `diagnostics.log` is the diagnostics log. It never records credentials or audio.

## Build

The build needs Rust 1.92 or newer:

```bash
cargo test --release --locked
```

```bash
cargo build --release --locked
```

The page in `web/`, GSAP and the Noto Sans SC subset are embedded in the EXE at compile time, so rebuild after changing the page.

To work on the interface without the backend, open `web/index.html` from any static file server. It then loads `mock.js` as a fake backend.

`vendor/cidermill-airplay` is a patched local copy of the protocol library and must stay in place for the build.

## Limitations

- Speakers that require a connection password are not supported. Their card shows a notice.
- The two speakers run as independent sessions, so their clocks can drift. Sample-accurate sync over long sessions is not guaranteed.
- Multi-speaker playback and calibration have been tested only against simulated receivers. They are not yet verified on real HomePods, microphones and rooms.
