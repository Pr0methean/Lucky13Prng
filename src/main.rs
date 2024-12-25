use std::io::{stdout, Write};
use rand_core::block::BlockRng64;
use rand_core::{OsRng, RngCore, TryRngCore};
use Lucky13Prng::Feistel;

fn main() {
    let mut osrng = OsRng::default();
    let mut rng = BlockRng64::new(Feistel::new(
        osrng.try_next_u64().unwrap(),
        osrng.try_next_u64().unwrap(),
        osrng.try_next_u64().unwrap()));
    let mut buffer = [0u8; 4096];
    loop {
        rng.fill_bytes(&mut buffer);
        stdout().write_all(&buffer).unwrap();
    }
}