# Changelog

All notable changes to this project will be documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses semantic versioning
within the usual pre-1.0 compatibility rules.

## [0.1.2] - 2026-10-17

### Changed

- The realtime stream applies the sync-packet drift fit as a resample ratio only once it is
  trustworthy: `DRIFT_MIN_SYNC_PACKETS` is now 16 (was 4), and a fit at the `MAX_DRIFT_PPM` clamp is
  never applied. Over Wi-Fi the early fit swung to the clamp and moved the buffer by about a
  millisecond a second. Until then the ratio is 1.0 and a placed stream's own correction
  (`MAX_CORRECTION_PPM`) holds it.
- The buffered stream re-places only on a sustained error, by the realtime playout's rule: an error
  past `RESYNC_THRESHOLD` that holds in one direction for `SUSTAINED_ERROR_TIME`, or at once past
  `GROSS_ERROR`. Other such packets are written as they are. This supersedes the 0.1.1 note that the
  buffered stream still re-places on a single packet.

### Added

- `BufferedStreamStats::ignored_outliers`.

## [0.1.1] - 2026-10-17

### Changed

- The receiver's playout scheduler re-places the stream only on a sustained error: one past
  `RESYNC_THRESHOLD` that holds for `SUSTAINED_ERROR_TIME` (0.1 s of consecutive audio, one
  direction), or at once past the new `GROSS_ERROR` (0.5 s). An isolated packet's error no longer
  causes a resync or enters the averaged correction.
  The buffered stream's own placement is unchanged: it still re-places on a single packet past
  `RESYNC_THRESHOLD`.

### Added

- `playout::GROSS_ERROR`, `playout::SUSTAINED_ERROR_TIME` and `PlayoutStats::ignored_outliers`.

## [0.1.0] - 2026-10-16

### Added

- AirPlay 2 sender and receiver as sans-io state machines: the RTSP/HTTP codec, TLV8, binary
  plists, `/info` and `Features`; HAP pair-setup (PIN and transient) and pair-verify on both
  sides; the encrypted control and event channels.
- URL playback and photos, realtime and buffered audio (ALAC, LPCM) with NTP and PTP timing, a
  shared multi-room timeline, now-playing metadata, `/command` and the MediaRemote data channel.
- AirPlay 1 audio in the clear (`et` 0), both ways.
- Optional features: `mirror` (screen mirroring), `legacy` (pre-HAP PIN pairing) and `raop-rsa`
  (AirPlay 1 `et` 1 for a sender).
- Thin blocking wrappers over `std::net` (`ControlChannel`, `EventChannel`, `TimingServer`), and
  four examples that run against each other on loopback.
- A Python binding for the codec, pairing and cipher building blocks.
- Golden vectors from pyatv, srptools, Python's `cryptography`, the `alac` crate and a Wireshark
  sample capture; scrubbed captures of real devices; never-panic tests and a libFuzzer target for
  every parser of peer bytes.

### Security

- Every parser of peer bytes refuses rather than panics, and every peer plist is parsed under
  nesting and size bounds.
- ALAC packets known to panic the `alac` decoder are refused first, and a panic is caught and
  returned as an error (with `panic = "unwind"`).
- PIN pair-setup is rate-limited per source address and receiver-wide; pairing secrets are wiped
  on drop.
