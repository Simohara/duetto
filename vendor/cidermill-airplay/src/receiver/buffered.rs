//! The buffered audio path of a receiver (`type: 103`), sans-io. Data arrives on TCP, in order, so
//! there is a length-prefixed frame decoder, per-packet decrypt, and a schedule, but no reorder
//! buffer.
//!
//! - Timing: a `SETRATEANCHORTIME` ([`crate::audio::control::RateAnchor`]) maps RTP time to a PTP
//!   timeline; the follower ([`crate::audio::ptp`]) turns that into a local instant.
//! - Packets come out undecoded; decode with [`super::audio::PacketDecoder`]. Sockets and sink
//!   writes are the host's.
//! - Cipher: ChaCha20-Poly1305 as in [`crate::audio::rtp::open_packet`] (`shk`). A wrapped-key
//!   Apple buffered stream's cipher is not implemented; `receiver::connection` answers it with 501.
//!
//! Unproven beyond this crate's own sender and receiver on one machine; no Apple buffered stream.

use std::collections::VecDeque;

use crate::audio::control::RateAnchor;
use crate::audio::rtp::{open_packet, BufferedFrameDecoder, BufferedHeader};
use crate::error::Result;
use crate::time::RtpTimestamp;

/// One decrypted buffered packet: its RTP timing and the (still-encoded) access unit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BufferedPacket {
    /// The 23-bit sequence number.
    pub sequence: u32,
    /// The RTP timestamp, for scheduling against the anchor.
    pub rtp_time: RtpTimestamp,
    /// The decrypted access unit (ALAC / AAC-LC / AAC-ELD), undecoded.
    pub payload: Vec<u8>,
}

/// What a buffered receiver has seen, for a log line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BufferedStats {
    /// Packets decrypted and queued.
    pub packets_opened: u64,
    /// Packets that did not decrypt or parse.
    pub packets_rejected: u64,
    /// Packets [`BufferedReceiver::flush`] dropped (a frame still being assembled counts once).
    pub packets_flushed: u64,
}

/// One buffered (`type: 103`) audio stream, sans-io. Feed the TCP bytes with [`Self::on_data`], set
/// the anchor from `SETRATEANCHORTIME` with [`Self::set_anchor`], and pop packets in order with
/// [`Self::next_packet`]; [`Self::play_nanos`] maps a packet's RTP time to a local instant.
#[derive(Debug)]
pub struct BufferedReceiver {
    key: [u8; 32],
    sample_rate: u32,
    frames: BufferedFrameDecoder,
    queue: VecDeque<BufferedPacket>,
    anchor: Option<RateAnchor>,
    stats: BufferedStats,
    /// The next whole frame was begun before a [`Self::flush`]: drop it.
    skip_frame: bool,
}

impl BufferedReceiver {
    /// A receiver for a buffered stream with the ChaCha20 `shk` and the format's sample rate.
    #[must_use]
    pub fn new(key: [u8; 32], sample_rate: u32) -> Self {
        Self {
            key,
            sample_rate: sample_rate.max(1),
            frames: BufferedFrameDecoder::new(),
            queue: VecDeque::new(),
            anchor: None,
            stats: BufferedStats::default(),
            skip_frame: false,
        }
    }

    /// Feeds TCP bytes: each complete frame is decrypted and queued in order. A frame that fails to
    /// decrypt or parse is dropped and counted.
    ///
    /// # Errors
    ///
    /// A malformed length prefix.
    pub fn on_data(&mut self, bytes: &[u8]) -> Result<()> {
        self.frames.push(bytes);
        while let Some(packet) = self.frames.next_packet()? {
            if std::mem::take(&mut self.skip_frame) {
                continue;
            }
            match open_packet(&self.key, &packet) {
                Ok(opened) => match BufferedHeader::parse(&opened.header) {
                    Ok(header) => {
                        self.stats.packets_opened += 1;
                        self.queue.push_back(BufferedPacket {
                            sequence: header.sequence,
                            rtp_time: header.timestamp,
                            payload: opened.payload,
                        });
                    }
                    Err(_) => self.stats.packets_rejected += 1,
                },
                Err(_) => self.stats.packets_rejected += 1,
            }
        }
        Ok(())
    }

    /// A `FLUSH` with no RTP time: drops every queued packet and the frame being assembled (read to
    /// its end to keep framing, then dropped). Returns how many went.
    pub fn flush(&mut self) -> u64 {
        let mut dropped = self.queue.len() as u64;
        self.queue.clear();
        if self.frames.buffered() > 0 {
            self.skip_frame = true;
            dropped += 1;
        }
        self.stats.packets_flushed += dropped;
        dropped
    }

    /// Records the `SETRATEANCHORTIME` anchor the stream plays against.
    pub fn set_anchor(&mut self, anchor: RateAnchor) {
        self.anchor = Some(anchor);
    }

    /// The anchor, if one has arrived.
    #[must_use]
    pub fn anchor(&self) -> Option<RateAnchor> {
        self.anchor
    }

    /// The next decrypted packet in order, if any.
    pub fn next_packet(&mut self) -> Option<BufferedPacket> {
        self.queue.pop_front()
    }

    /// The local instant (ns) at which `rtp_time` plays; `ptp_offset_nanos` is local minus master
    /// ([`crate::audio::ptp::one_way_offset`]). `None` until an anchor arrives, if it pauses
    /// (rate 0), or if the offset puts the instant past `i128`; any other rate plays at 1.
    #[must_use]
    pub fn play_nanos(&self, rtp_time: RtpTimestamp, ptp_offset_nanos: i128) -> Option<i128> {
        let anchor = self.anchor?;
        if anchor.rate == 0 {
            return None;
        }
        // The signed difference places it before or after the anchor.
        let delta_frames = i64::from(rtp_time.signed_frames_since(anchor.rtp_time));
        let delta_nanos = i128::from(delta_frames) * 1_000_000_000 / i128::from(self.sample_rate);
        let master_nanos = i128::try_from(anchor.network_time.to_nanos()).ok()? + delta_nanos;
        master_nanos.checked_add(ptp_offset_nanos)
    }

    /// What it has seen.
    #[must_use]
    pub fn stats(&self) -> BufferedStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio::control::RateAnchor;
    use crate::audio::ptp::NetworkTime;
    use crate::audio::rtp::{frame_buffered, BufferedHeader, PacketSealer};

    const KEY: [u8; 32] = [7u8; 32];
    const RATE: u32 = 44_100;

    fn sealed_frame(
        sealer: &mut PacketSealer,
        sequence: u32,
        rtp_time: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let header = BufferedHeader::new(sequence, RtpTimestamp::new(rtp_time), 0).encode();
        let packet = sealer.seal(&header, payload).unwrap();
        frame_buffered(&packet).unwrap()
    }

    #[test]
    fn decrypts_and_delivers_buffered_packets_in_order() {
        let mut sealer = PacketSealer::new(&KEY);
        let mut rx = BufferedReceiver::new(KEY, RATE);
        // Two packets, fed as one TCP chunk and then split across a chunk boundary.
        let mut stream = sealed_frame(&mut sealer, 1, 1000, b"first");
        let second = sealed_frame(&mut sealer, 2, 1480, b"second");
        stream.extend_from_slice(&second[..3]);
        rx.on_data(&stream).unwrap();
        rx.on_data(&second[3..]).unwrap();
        let a = rx.next_packet().unwrap();
        assert_eq!(
            (a.sequence, a.rtp_time.get(), a.payload.as_slice()),
            (1, 1000, b"first".as_slice())
        );
        let b = rx.next_packet().unwrap();
        assert_eq!(
            (b.sequence, b.rtp_time.get(), b.payload.as_slice()),
            (2, 1480, b"second".as_slice())
        );
        assert!(rx.next_packet().is_none());
        assert_eq!(rx.stats().packets_opened, 2);
    }

    #[test]
    fn a_bad_frame_is_dropped_and_counted() {
        let mut rx = BufferedReceiver::new(KEY, RATE);
        let mut junk = vec![0u8; 64];
        let framed = frame_buffered(&junk).unwrap();
        junk = framed;
        rx.on_data(&junk).unwrap();
        assert!(rx.next_packet().is_none());
        assert_eq!(rx.stats().packets_rejected, 1);
        assert_eq!(rx.stats().packets_opened, 0);
    }

    #[test]
    fn a_flush_drops_what_is_queued_and_the_frame_half_read() {
        let mut sealer = PacketSealer::new(&KEY);
        let mut rx = BufferedReceiver::new(KEY, RATE);
        let queued = sealed_frame(&mut sealer, 1, 1000, b"queued");
        let half = sealed_frame(&mut sealer, 2, 1352, b"half read");
        let after = sealed_frame(&mut sealer, 3, 1704, b"after");
        let mut first = queued.clone();
        first.extend_from_slice(&half[..5]);
        rx.on_data(&first).unwrap();
        assert_eq!(rx.flush(), 2, "the queued packet and the half-read frame");
        // The half-read frame is read to its end and dropped; the next plays.
        let mut rest = half[5..].to_vec();
        rest.extend_from_slice(&after);
        rx.on_data(&rest).unwrap();
        let next = rx.next_packet().expect("the frame after the FLUSH");
        assert_eq!(next.payload, b"after");
        assert!(rx.next_packet().is_none());
        assert_eq!(rx.stats().packets_flushed, 2);
        // Nothing half read: nothing to skip.
        assert_eq!(rx.flush(), 0);
        rx.on_data(&sealed_frame(&mut sealer, 4, 2056, b"later"))
            .unwrap();
        assert_eq!(rx.next_packet().unwrap().payload, b"later");
    }

    #[test]
    fn play_time_follows_the_anchor_and_the_ptp_offset() {
        let mut rx = BufferedReceiver::new(KEY, RATE);
        let rtp = RtpTimestamp::new;
        // No anchor yet: no schedule.
        assert_eq!(rx.play_nanos(rtp(1000), 0), None);
        // Anchor: rtp 1000 plays at master 5 s; the follower says local is 2 s behind master.
        let anchor = RateAnchor::play(NetworkTime::from_nanos(5_000_000_000), 42, rtp(1000));
        rx.set_anchor(anchor);
        let offset = -2_000_000_000i128; // local − master (the follower's convention)
        assert_eq!(rx.play_nanos(rtp(1000), offset), Some(3_000_000_000));
        // One packet later (441 frames = 10 ms) plays 10 ms later.
        assert_eq!(rx.play_nanos(rtp(1441), offset), Some(3_010_000_000));
        // Before the anchor, across the RTP wrap, plays earlier.
        rx.set_anchor(RateAnchor::play(
            NetworkTime::from_nanos(5_000_000_000),
            42,
            rtp(220),
        ));
        assert_eq!(
            rx.play_nanos(rtp(220).wrapping_sub(441), offset),
            Some(2_990_000_000)
        );
        // A pause anchor (rate 0) schedules nothing.
        rx.set_anchor(RateAnchor::pause(
            NetworkTime::from_nanos(5_000_000_000),
            42,
            rtp(1000),
        ));
        assert_eq!(rx.play_nanos(rtp(1000), offset), None);
    }
}
