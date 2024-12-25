#![feature(variant_count)]

use std::hash::Hasher;
use std::mem::{variant_count};
use std::sync::OnceLock;
use bit_reverse::ParallelReverse;
use permutations::Permutations;
use rand_core::block::BlockRngCore;

type Block = u64;

// These are the first 48 hex digits of pi * 1 << 62
pub const NOTHING_UP_MY_SLEEVE: Block = 0xc90f_daa2_2168_c234;
pub const NOTHING_UP_MY_SLEEVE_2: Block = 0xc4c6_628b_80dc_1cd1;
pub const NOTHING_UP_MY_SLEEVE_3: Block = 0x2902_4e08_8a67_cc74;

#[repr(usize)]
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

pub const THIRTEEN_FACTORIAL: Block = 6227020800;
pub const PRIME_NEAR_THIRTEEN_FACTORIAL: Block = 6227020777;
pub const BLOCK_BITS: u8 = (8 * size_of::<Block>()) as u8;
pub const ROUND_MULTIPLES: [u8; 13] = [2, BLOCK_BITS - 3, 5, BLOCK_BITS - 7, 11, BLOCK_BITS - 17, 19, BLOCK_BITS - 23, 29, BLOCK_BITS - 31, 37, BLOCK_BITS - 41, 43];

pub const ROUND_IVS: [Block; 2] = [
    NOTHING_UP_MY_SLEEVE,
    NOTHING_UP_MY_SLEEVE_2
];

const fn build_rotation_amounts() -> [u8; 13] {
    let mut amounts = [0; 13];
    amounts[Mutation::Rotate32 as usize] = BLOCK_BITS - 32;
    amounts[Mutation::Rotate16 as usize] = 16;
    amounts[Mutation::Rotate8 as usize] = BLOCK_BITS - 8;
    amounts[Mutation::Rotate4 as usize] = 4;
    amounts[Mutation::Rotate2 as usize] = BLOCK_BITS - 2;
    amounts[Mutation::Rotate1 as usize] = 1;
    amounts
}

const ROTATION_AMOUNTS: [u8; 13] = build_rotation_amounts();

const fn build_stripe_masks() -> [Block; 13] {
    let mut amounts = [0; 13];
    amounts[Mutation::Stripe32 as usize] = 0x00000000FFFFFFFF;
    amounts[Mutation::Stripe16 as usize] = 0xFFFF0000FFFF0000;
    amounts[Mutation::Stripe8 as usize] = 0x00FF00FF00FF00FF;
    amounts[Mutation::Stripe4 as usize] = 0xF0F0F0F0F0F0F0F0;
    amounts[Mutation::Stripe2 as usize] = 0x3333333333333333;
    amounts[Mutation::Stripe1 as usize] = 0xAAAAAAAAAAAAAAAA;
    amounts
}

const STRIPE_MASKS: [Block; 13] = build_stripe_masks();
const REVERSE: usize = Mutation::Reverse as usize;

#[inline(always)]
pub fn permutation_step(input: Block, mutation: usize) -> Block {
    match mutation {
        REVERSE => ParallelReverse::swap_bits(input),
        _ => input.rotate_left(ROTATION_AMOUNTS[mutation] as u32) ^ STRIPE_MASKS[mutation]
    }
}

const PERMUTATIONS: OnceLock<Permutations> = OnceLock::new();

#[inline(always)]
pub fn permutation(input: Block, permutation_index: Block) -> Block {
    let mutations = PERMUTATIONS.get_or_init(|| Permutations::new(variant_count::<Mutation>()))
        .get(permutation_index as usize).unwrap();
    (0..variant_count::<Mutation>()).fold(input, |input, index|
        permutation_step(input, mutations.apply(index)))
}

pub const ROUNDS: Block = ROUND_MULTIPLES.len() as Block;

pub struct Feistel {
    k1: Block,
    k2: Block,
    counter: u128
}

impl Feistel {
    pub fn new(k1: Block, k2: Block, k3: Block) -> Self {
        Self { k1, k2, counter: k3.into() }
    }

    #[inline(always)]
    fn permute(&mut self, input: Block) -> Block {
        let (counter_low, counter_high) = self.counter_as_blocks();
        let mut l = NOTHING_UP_MY_SLEEVE.wrapping_add(counter_low.wrapping_add(self.k2.rotate_right(13)));
        let mut r = input;
        let mut final_u: Block = 0;
        let round_key_base = self.k1.wrapping_add(counter_high);
        let permuted_k2 = permutation(NOTHING_UP_MY_SLEEVE_2, self.k2 % PRIME_NEAR_THIRTEEN_FACTORIAL);
        for round in 0..ROUNDS {
            let k = (round_key_base.rotate_left(ROUND_MULTIPLES[round as usize % ROUND_MULTIPLES.len()] as u32)) ^ permuted_k2;
            let t = permutation(k, r % THIRTEEN_FACTORIAL);
            let u = t ^ l;
            l = r;
            r = u;
            final_u = u;
        }
        self.k1 = self.k1.rotate_right(7) ^ l;
        self.k2 ^= final_u;
        self.counter += 1;
        permutation(l, r % PRIME_NEAR_THIRTEEN_FACTORIAL)
    }

    #[inline(always)]
    fn counter_as_blocks(&self) -> (u64, u64) {
        let counter_bytes = self.counter.to_ne_bytes();
        let counter_low = Block::from_ne_bytes(counter_bytes[0..=7].try_into().unwrap());
        let counter_high = Block::from_ne_bytes(counter_bytes[8..=15].try_into().unwrap());
        (counter_low, counter_high)
    }
}

impl BlockRngCore for Feistel {

    type Item = Block;
    type Results = [Block; 2];

    #[inline(always)]
    fn generate(&mut self, results: &mut Self::Results) {
        results[0] = self.permute(NOTHING_UP_MY_SLEEVE_3);
        results[1] = self.k1.rotate_right(32) ^ self.k2;
    }
}

impl Hasher for Feistel {
    #[inline(always)]
    fn finish(&self) -> u64 {
        let (counter_low, counter_high) = self.counter_as_blocks();
        self.k1.wrapping_add(counter_low.wrapping_mul(NOTHING_UP_MY_SLEEVE)) ^ (self.k2.wrapping_add(counter_high))
    }

    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        self.permute(bytes.len() as Block);
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
        let feistel = Feistel::new(0, 0, 0);
        let hash = feistel.finish();
        println!("[] -> {:016x}", hash);
        assert!(hashes.insert(feistel.finish()));
        for b1 in 0..=u8::MAX {
            let mut feistel = Feistel::new(0, 0, 0);
            feistel.write(&[b1]);
            let hash = feistel.finish();
            println!("[{:02x}] -> {:016x}", b1, hash);
            assert!(hashes.insert(hash));
            for b2 in 0..=u8::MAX {
                let mut feistel = Feistel::new(0, 0, 0);
                feistel.write(&[b1, b2]);
                let hash = feistel.finish();
                assert!(hashes.insert(hash));
                println!("[{:02x}, {:02x}] -> {}", b1, b2, hash);
                for b3 in 0..=u8::MAX {
                    let mut feistel = Feistel::new(0, 0, 0);
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
