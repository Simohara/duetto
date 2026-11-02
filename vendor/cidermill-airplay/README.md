# cidermill-airplay

[![pipeline status](https://gitlab.com/timrs2998/cidermill-airplay/badges/main/pipeline.svg)](https://gitlab.com/timrs2998/cidermill-airplay/-/pipelines)
[![crates.io](https://img.shields.io/crates/v/cidermill-airplay)](https://crates.io/crates/cidermill-airplay)
[![docs.rs](https://docs.rs/cidermill-airplay/badge.svg)](https://docs.rs/cidermill-airplay)

**AirPlay 2 for Rust: the sender and the receiver side of the protocol, sans-io.** Pairing, the
encrypted control channel, URL playback, realtime and buffered audio, timing, metadata and
(behind a feature) screen mirroring are byte-in/byte-out state machines that open no socket, so
they run over any transport, blocking or async, and are fuzzed. Thin blocking wrappers over
`std::net` cover the common case. It is an independent implementation of a protocol Apple does
not publish, written for the Cidermill Windows app and usable on its own.

## Install

```sh
cargo add cidermill-airplay
```

Python:

```sh
python -m pip install cidermill-airplay
```

Wheels are published for Linux x86_64 only. Elsewhere pip builds the package from source,
which needs a Rust toolchain ([rustup](https://rustup.rs)).

Minimum Rust: 1.89. Functions that need randomness take `&mut dyn CryptoRng` (`rand_core` 0.10,
re-exported); `OsRng` is the operating system's.

## Quickstart

```rust,no_run
use cidermill_airplay::pairing::HapCredentials;
use cidermill_airplay::{Auth, ControlChannel, OsRng};

let credentials = HapCredentials::parse("...")?; // from a PIN pairing
let mut channel = ControlChannel::builder("192.0.2.10").connect()?;
channel.authenticate(Auth::Stored(&credentials), &mut OsRng)?;
let _playback = channel.start_url_playback("http://192.0.2.1/movie.mp4", 0.0)?;
```

The [examples](https://gitlab.com/timrs2998/cidermill-airplay/-/tree/main/examples) are complete
programs that run against each other on loopback:

```sh
cargo run --example receiver -- 127.0.0.1:7000 1234     # prints every event, plays audio in time
cargo run --example pair -- 127.0.0.1:7000 1234          # prints credentials
cargo run --example play_url -- 127.0.0.1:7000 http://192.0.2.1/a.mp4 CREDENTIALS
cargo run --example send_audio -- 127.0.0.1:7000 CREDENTIALS 5
```

## What it covers

| Area | Sender | Receiver |
|---|---|---|
| HAP pairing: PIN, transient, pair-verify | yes | yes, with a rate-limited PIN |
| Legacy PIN pairing | with `legacy` | no |
| Encrypted control and event channels | yes | yes |
| URL playback (`/play`, `/rate`, `/scrub`, `/playback-info`) | yes | yes, as events for your player |
| Photos (`PUT /photo`) | no | yes |
| Realtime audio (ALAC, LPCM) | yes | yes, decoded and placed on the sender's timeline |
| Buffered audio (PTP) | yes | yes, opt-in, placed by its anchor |
| Multi-room: one timeline, scheduled playout | yes | yes |
| Timing: NTP server and follower, PTP messages, clock filter | yes | yes |
| Now-playing metadata, artwork, progress, `/command` | yes | yes |
| MediaRemote data channel | yes | yes |
| Screen mirroring (H.264, keyed from the pairing) | with `mirror` | with `mirror` |
| AirPlay 1 audio (`et` 0, in the clear) | yes | yes, opt-in, no pairing |
| AirPlay 1 audio `et` 1 (AirPort Express public key) | with `raop-rsa` | no |
| `_airplay._tcp` / `_raop._tcp` TXT records | no | yes (no mDNS responder) |

Apple TVs and HomePods play realtime audio from this crate. An Apple TV refuses pair-setup on
the AirPlay port, so its credential comes from Companion pairing (the pairing state machines take
Companion's message shapes). URL video, buffered audio and mirroring to Apple devices need FairPlay
sender authentication, which this crate does not implement, and Apple senders do not stream to its
receiver for the same reason. Between two copies of this crate everything above works, and
pyatv's sender has streamed audio to the receiver (observed by hand, not an automated test).

The receiver decodes ALAC with the third-party `alac` crate, which can panic on hostile packets.
Shapes known to panic it are refused first, and a panic is caught and returned as an error; that
needs `panic = "unwind"` (the default). Under `panic = "abort"` a bad ALAC packet ends the process.

## How it compares

| Project | Language | Sender | Receiver |
|---|---|---|---|
| cidermill-airplay | Rust | yes | yes |
| [pyatv](https://github.com/postlund/pyatv) | Python | yes, plus Companion and DMAP | no |
| [shairport-sync](https://github.com/mikebrady/shairport-sync) | C | no | audio |

## How it is tested

- **Golden vectors from outside the code under test**, in `tests/fixtures/` with their generators
  in `tools/`: pyatv 0.18.0's own sender code (HAP session framing, realtime audio, DMAP,
  MediaRemote, legacy pairing), srptools driven with pyatv's HAP parameters for the receiver's
  SRP, Python's `cryptography` and `hashlib` for the mirroring keys and AirPlay 1's RSA, the
  `alac` crate's reference packet, and PTPv2 messages from a Wireshark sample capture. A change
  that moves a byte needs a new external reference, not a new expected value.
- **Captures of real devices**: an iPhone sending to a lab receiver, an Apple TV's stream `SETUP`
  replies and PTP traffic, and `/info` replies from an Apple TV and a HomePod, with names,
  addresses, keys and identifiers replaced by placeholders.
- **Hostile input**: every parser of peer bytes has an arbitrary-bytes-never-panic test
  (`tests/*_never_panic.rs`) and a libFuzzer target (`fuzz/`).
- **The examples** pair, play and stream against the example receiver on loopback
  (`tests/examples_loopback.rs`).

## Features

All off by default, so a build that only pairs and plays audio pulls in no SHA-1, AES-GCM, AES-CTR
or AES-CBC.

- `mirror` — screen mirroring: stream `SETUP`, the packet reader and writer, H.264 framing and
  the AES-CTR stream cipher; also AES-CBC realtime audio from a sender whose key arrives wrapped.
- `legacy` — pre-HAP PIN pairing.
- `raop-rsa` — AirPlay 1 `et` 1 for a sender: the AirPort Express public key, RSA-OAEP with SHA-1
  and AES-CBC.
- `test-server` — the SRP test servers, for tests only.

## Python

[`bindings/cidermill-airplay-py`](https://gitlab.com/timrs2998/cidermill-airplay/-/tree/main/bindings/cidermill-airplay-py)
wraps the codec, pairing and cipher building blocks for protocol work in Python (PyPI name
`cidermill-airplay`).

## Contributing

See [CONTRIBUTING.md](https://gitlab.com/timrs2998/cidermill-airplay/-/blob/main/CONTRIBUTING.md).
This crate contains no FairPlay implementation and will not accept one.

## AI disclosure

This project was created with the help of AI — specifically Anthropic's
[Claude](https://claude.com/claude-code). That includes the library code, the Python binding,
tests, fuzz targets, CI configuration, and documentation, with design decisions and validation
made by a human. See
[AGENTS.md](https://gitlab.com/timrs2998/cidermill-airplay/-/blob/main/AGENTS.md) for the
conventions AI contributors are expected to follow.

## License

**GPL-3.0-or-later** (see
[LICENSE](https://gitlab.com/timrs2998/cidermill-airplay/-/blob/main/LICENSE)). In short: use,
study, and change it freely; if you distribute it, or anything built on it, pass the same freedoms
on, source included. The copyright holder can grant separate terms; open an issue to ask.

The library's code is original to this project. Other implementations were read for how the
protocol behaves and their output pins this crate's bytes in tests, but none of their code was
copied. Test data taken from elsewhere names its source in the fixture.

## Acknowledgements

- [pyatv](https://github.com/postlund/pyatv) (MIT) — the reference sender whose own output is
  most of the golden vectors.
- [shairport-sync](https://github.com/mikebrady/shairport-sync) (MIT-style) and
  [openairplay/airplay2-receiver](https://github.com/openairplay/airplay2-receiver) (no licence
  published) — open receivers, read for behaviour; none of their code is here.
- The [openairplay AirPlay specification](https://openairplay.github.io/airplay-spec/) and
  Emanuele Cozzi's *AirPlay 2 Internals* notes — protocol documentation; a published capture
  from the latter is quoted in `tests/fixtures/audio-apple-captures.json`.
- [srptools](https://github.com/idlesign/srptools) (BSD-3-Clause) — an independent SRP-6a that
  generates the receiver's pairing vectors.
- The [`alac`](https://crates.io/crates/alac) crate (MIT OR Apache-2.0) — the receiver's ALAC
  decoder, and a reference packet in the tests (`tests/fixtures/alac-crate-0.5.0/NOTICE.md`).
- The Wireshark project's [sample captures](https://wiki.wireshark.org/SampleCaptures) — the PTPv2
  messages the PTP parser is checked against.

AirPlay, AirPort Express, Apple TV, HomePod and iPhone are trademarks of Apple Inc. This project
is not affiliated with or endorsed by Apple.
