//! RAOP retransmission queue: retain exactly the sent ciphertext, bounded like pyatv.
use cidermill_airplay::audio::rtp::{RetransmitRequest, retransmit_reply};
use std::collections::VecDeque;
const CAPACITY: usize = 1000;
pub struct Backlog {
    packets: VecDeque<(u16, Vec<u8>)>,
}
impl Backlog {
    pub fn new() -> Self {
        Self {
            packets: VecDeque::with_capacity(CAPACITY),
        }
    }
    pub fn remember(&mut self, packet: Vec<u8>) {
        if packet.len() < 4 {
            return;
        }
        let sequence = u16::from_be_bytes([packet[2], packet[3]]);
        if self.packets.len() == CAPACITY {
            self.packets.pop_front();
        }
        self.packets.push_back((sequence, packet));
    }
    pub fn replies(&self, request: &[u8]) -> Vec<Vec<u8>> {
        let Ok(request) = RetransmitRequest::parse(request) else {
            return Vec::new();
        };
        request
            .lost_sequences()
            .filter_map(|sequence| {
                self.packets
                    .iter()
                    .rev()
                    .find(|(stored, _)| *stored == sequence)
                    .map(|(_, packet)| retransmit_reply(sequence, packet))
            })
            .collect()
    }
}
/// Drain a bounded number of control requests; reply only to the chosen IP.
pub fn poll(
    socket: &std::net::UdpSocket,
    receiver: std::net::Ipv4Addr,
    backlog: &Backlog,
) -> std::io::Result<()> {
    for _ in 0..64 {
        let mut request = [0u8; 2048];
        match socket.recv_from(&mut request) {
            Ok((length, peer)) if peer.ip() == std::net::IpAddr::V4(receiver) => {
                for reply in backlog.replies(&request[..length]) {
                    let _ = socket.send_to(&reply, peer);
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retransmits_exact_ciphertext_and_handles_wrap() {
        let mut b = Backlog::new();
        b.remember(vec![0x80, 0xe0, 0xff, 0xff, 5, 6]);
        b.remember(vec![0x80, 0x60, 0, 0, 7, 8]);
        let q = RetransmitRequest::new(2, 0xffff, 2).encode();
        assert_eq!(
            b.replies(&q),
            vec![
                vec![0x80, 0xd6, 0xff, 0xff, 0x80, 0xe0, 0xff, 0xff, 5, 6],
                vec![0x80, 0xd6, 0, 0, 0x80, 0x60, 0, 0, 7, 8]
            ]
        );
        assert!(b.replies(&[1, 2, 3]).is_empty());
    }
    #[test]
    fn backlog_evicts_oldest() {
        let mut b = Backlog::new();
        for seq in 0..1001u16 {
            let [a, c] = seq.to_be_bytes();
            b.remember(vec![0x80, 0x60, a, c]);
        }
        assert!(
            b.replies(&RetransmitRequest::new(0, 0, 1).encode())
                .is_empty()
        );
        assert_eq!(
            b.replies(&RetransmitRequest::new(0, 1000, 1).encode())
                .len(),
            1
        );
    }
    #[test]
    fn retransmit_over_udp_matches_original_packet() {
        use std::{
            net::{Ipv4Addr, UdpSocket},
            time::Duration,
        };
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.set_nonblocking(true).unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut b = Backlog::new();
        b.remember(vec![0x80, 0x60, 0, 42, 9, 8, 7]);
        receiver
            .send_to(
                &RetransmitRequest::new(5, 42, 1).encode(),
                sender.local_addr().unwrap(),
            )
            .unwrap();
        for _ in 0..20 {
            poll(&sender, Ipv4Addr::LOCALHOST, &b).unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut reply = [0u8; 128];
        let (n, _) = receiver.recv_from(&mut reply).unwrap();
        assert_eq!(
            &reply[..n],
            &[0x80, 0xd6, 0, 42, 0x80, 0x60, 0, 42, 9, 8, 7]
        );
    }
}
