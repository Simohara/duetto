//! The operating system's random number generator, as an infallible [`rand_core::CryptoRng`].

use rand_core::{Infallible, Rng as _, TryCryptoRng, TryRng, UnwrapErr};

/// The operating system's random number generator ([`getrandom::SysRng`]) as an infallible
/// [`CryptoRng`](rand_core::CryptoRng): `&mut OsRng` goes wherever this crate takes randomness.
///
/// Panics if the operating system cannot supply random bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl TryRng for OsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(UnwrapErr(getrandom::SysRng).next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(UnwrapErr(getrandom::SysRng).next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        UnwrapErr(getrandom::SysRng).fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::OsRng;
    use rand_core::CryptoRng;

    #[test]
    fn os_rng_fills_through_the_crates_rng_parameter() {
        fn draw(rng: &mut dyn CryptoRng) -> [u8; 32] {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        }
        assert_ne!(draw(&mut OsRng), draw(&mut OsRng));
    }
}
