#![feature(variant_count)]

use std::hash::Hasher;
use std::mem::variant_count;
use std::ops::Shr;
use bit_reverse::ParallelReverse;
use permutations::Permutations;
use rand_core::block::BlockRngCore;
use rand_core::RngCore;

type Block = u64;

// These are the first 48 hex digits of pi * 1 << 62
pub const NOTHING_UP_MY_SLEEVE: Block = 0xc90f_daa2_2168_c234;
pub const NOTHING_UP_MY_SLEEVE_2: Block = 0xc4c6_628b_80dc_1cd1;
pub const NOTHING_UP_MY_SLEEVE_3: Block = 0x2902_4e08_8a67_cc74;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Mutation {
    Rotate32,
    Rotate16,
    Rotate8,
    Rotate4,
    Rotate2,
    Rotate1,
    Stripe32,
    Stripe16,
    Stripe8,
    Stripe4,
    Stripe2,
    Stripe1,
    Reverse
}

pub const ALL_MUTATIONS: [Mutation; 13] = [
    Mutation::Rotate32,
    Mutation::Stripe1,
    Mutation::Rotate16,
    Mutation::Reverse,
    Mutation::Stripe2,
    Mutation::Rotate8,
    Mutation::Stripe4,
    Mutation::Rotate4,
    Mutation::Stripe8,
    Mutation::Rotate2,
    Mutation::Rotate1,
    Mutation::Stripe32,
    Mutation::Stripe16,
];

pub const THIRTEEN_FACTORIAL: Block = 6227020800;
pub const PRIME_NEAR_THIRTEEN_FACTORIAL: Block = 6227020777;
pub const BLOCK_BITS: u32 = (8 * size_of::<Block>()) as u32;
pub const ROUND_MULTIPLES: [u32; 13] = [2, BLOCK_BITS - 3, 5, BLOCK_BITS - 7, 11, BLOCK_BITS - 17, 19, BLOCK_BITS - 23, 29, BLOCK_BITS - 31, 37, BLOCK_BITS - 41, 43];

pub const ROUND_IVS: [Block; 2] = [
    NOTHING_UP_MY_SLEEVE,
    NOTHING_UP_MY_SLEEVE_2
];

pub fn permutation_step(input: Block, mutation: Mutation) -> Block {
    match mutation {
        Mutation::Rotate32 => input.rotate_left(32),
        Mutation::Rotate16 => input.rotate_right(16),
        Mutation::Rotate8 => input.rotate_left(8),
        Mutation::Rotate4 => input.rotate_right(4),
        Mutation::Rotate2 => input.rotate_left(2),
        Mutation::Rotate1 => input.rotate_right(1),
        Mutation::Stripe32 => input ^ 0x00000000FFFFFFFF,
        Mutation::Stripe16 => input ^ 0xFFFF0000FFFF0000,
        Mutation::Stripe8 => input ^ 0x00FF00FF00FF00FF,
        Mutation::Stripe4 => input ^ 0xF0F0F0F0F0F0F0F0,
        Mutation::Stripe2 => input ^ 0x3333333333333333,
        Mutation::Stripe1 => input ^ 0xAAAAAAAAAAAAAAAA,
        Mutation::Reverse => ParallelReverse::swap_bits(input),
    }
}

pub fn permutation(input: Block, permutation_index: Block) -> Block {
    let mutations = Permutations::new(variant_count::<Mutation>()).get((permutation_index) as usize).unwrap();
    mutations.permute(&ALL_MUTATIONS).into_iter().fold(input, permutation_step)
}

pub fn round_key(k1: Block, k2: Block, round: Block) -> Block {
    let permuted_k2 = permutation(NOTHING_UP_MY_SLEEVE_2, k2 % PRIME_NEAR_THIRTEEN_FACTORIAL);
    (k1.rotate_left(ROUND_MULTIPLES[round as usize % ROUND_MULTIPLES.len()])) ^ permuted_k2
}

pub const ROUNDS: u32 = ROUND_MULTIPLES.len() as u32 * 2 + 1;

pub struct Feistel {
    k1: Block,
    k2: Block
}

impl Feistel {
    pub fn new(k1: Block, k2: Block) -> Self {
        Self { k1, k2 }
    }

    fn permute(&mut self, input: Block) -> Block {
        let mut l: Block = 0;
        let mut r: Block = 0;
        for iv in ROUND_IVS {
            l = iv;
            r = input;
            let mut u: Block = 0;
            for round in 0..ROUNDS {
                let mut t: Block;
                let k = round_key(self.k1, self.k2, round as Block);
                t = permutation(k, r % THIRTEEN_FACTORIAL);
                u = t ^ l;
                l = r;
                r = u;
            }
            self.k2 = self.k2 ^ u;
        }
        self.k1 = self.k1.rotate_right(7) ^ l;
        permutation(l, r % PRIME_NEAR_THIRTEEN_FACTORIAL)
    }
}

impl BlockRngCore for Feistel {

    type Item = Block;
    type Results = [Block; 1];

    fn generate(&mut self, results: &mut Self::Results) {
        results[0] = self.permute(NOTHING_UP_MY_SLEEVE_3);
    }
}

impl Hasher for Feistel {
    fn finish(&self) -> u64 {
        self.k1 ^ self.k2
    }

    fn write(&mut self, bytes: &[u8]) {
        self.permute(bytes.len() as Block ^ NOTHING_UP_MY_SLEEVE);
        for byte in bytes {
            self.permute(*byte as Block);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::hash::Hasher;
    use crate::Feistel;

    #[test]
    fn test_hash_collisions() {
        let mut hashes = HashSet::new();
        let mut last_digits = String::with_capacity((u8::MAX as usize + 2) * (u8::MAX as usize + 1));
        let feistel = Feistel::new(0, 0);
        let hash = feistel.finish();
        println!("[] -> {:016x}", hash);
        assert!(hashes.insert(feistel.finish()));
        for b1 in 0..=u8::MAX {
            let mut feistel = Feistel::new(0, 0);
            feistel.write(&[b1]);
            let hash = feistel.finish();
            println!("[{:02x}] -> {:016x}", b1, hash);
            assert!(hashes.insert(hash));
            for b2 in 0..=u8::MAX {
                let mut feistel = Feistel::new(0, 0);
                feistel.write(&[b1, b2]);
                let hash = feistel.finish();
                assert!(hashes.insert(hash));
                println!("[{:02x}, {:02x}] -> {}", b1, b2, hash);
                for b3 in 0..=u8::MAX {
                    let mut feistel = Feistel::new(0, 0);
                    feistel.write(&[b1, b2, b3]);
                    let hash = feistel.finish();
                    assert!(hashes.insert(hash));
                    let hex = format!("{:016x}", hash);
                    println!("[{:02x}, {:02x}, {:02x}] -> {}", b1, b2, b3, hex);
                    last_digits.push(hex.as_bytes()[15] as char);
                }
                last_digits.push('\n');
            }
        }
        println!("{}", last_digits);
    }
}
