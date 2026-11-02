//! Small helpers for the ids a sender or receiver names itself with.

use rand_core::CryptoRng;

/// A random MAC-shaped id (`deviceid`): upper case with colons, locally administered, unicast.
#[must_use]
pub fn random_mac(rng: &mut dyn CryptoRng) -> String {
    let mut mac = [0u8; 6];
    rng.fill_bytes(&mut mac);
    mac[0] = (mac[0] | 0x02) & 0xFE;
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A random version 4 UUID, upper case with hyphens, as Apple writes them.
#[must_use]
pub fn uuid_v4(rng: &mut dyn CryptoRng) -> String {
    let mut uuid = [0u8; 16];
    rng.fill_bytes(&mut uuid);
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    crate::pairing::uppercase_uuid(&uuid)
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn a_random_mac_is_locally_administered_unicast() {
        let mut rng = StdRng::seed_from_u64(1);
        for _ in 0..64 {
            let mac = super::random_mac(&mut rng);
            assert_eq!(mac.len(), 17);
            let first = u8::from_str_radix(&mac[..2], 16).unwrap();
            assert_eq!(first & 0x03, 0x02, "{mac}");
            assert_eq!(mac, mac.to_ascii_uppercase());
        }
    }

    #[test]
    fn a_uuid_is_version_4_and_upper_case() {
        let mut rng = StdRng::seed_from_u64(2);
        let a = super::uuid_v4(&mut rng);
        let b = super::uuid_v4(&mut rng);
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!(matches!(&a[19..20], "8" | "9" | "A" | "B"), "{a}");
        assert_eq!(a, a.to_ascii_uppercase());
    }
}
