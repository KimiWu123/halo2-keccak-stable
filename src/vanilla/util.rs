//! Utility traits, functions used in the crate.
use crate::util::eth_types::{Field, ToScalar, Word};

use super::param::*;

/// Rotates a word that was split into parts to the right
pub fn rotate<T>(parts: Vec<T>, count: usize, part_size: usize) -> Vec<T> {
    let mut rotated_parts = parts;
    rotated_parts.rotate_right(get_rotate_count(count, part_size));
    rotated_parts
}

/// The words that absorb data
pub fn get_absorb_positions() -> Vec<(usize, usize)> {
    let mut absorb_positions = Vec::new();
    for j in 0..5 {
        for i in 0..5 {
            if i + j * 5 < 17 {
                absorb_positions.push((i, j));
            }
        }
    }
    absorb_positions
}

/// Converts bytes into bits
pub fn into_bits(bytes: &[u8]) -> Vec<u8> {
    let mut bits: Vec<u8> = vec![0; bytes.len() * 8];
    for (byte_idx, byte) in bytes.iter().enumerate() {
        for idx in 0u64..8 {
            bits[byte_idx * 8 + (idx as usize)] = (*byte >> idx) & 1;
        }
    }
    bits
}

/// Pack bits in the range [0,BIT_SIZE[ into a sparse keccak word
pub fn pack<F: Field>(bits: &[u8]) -> F {
    pack_with_base(bits, BIT_SIZE)
}

/// Pack bits in the range [0,BIT_SIZE[ into a sparse keccak word with the
/// specified bit base
pub fn pack_with_base<F: Field>(bits: &[u8], base: usize) -> F {
    let base = F::from(base as u64);
    bits.iter().rev().fold(F::ZERO, |acc, &bit| acc * base + F::from(bit as u64))
}

/// Unpack a sparse keccak word into bits in the range [0,BIT_SIZE[
pub fn unpack<F: Field>(packed: F) -> [u8; NUM_BITS_PER_WORD] {
    let mut bits = [0; NUM_BITS_PER_WORD];
    let packed = Word::from_little_endian(packed.to_bytes_le().as_ref());
    let mask = Word::from(BIT_SIZE - 1);
    for (idx, bit) in bits.iter_mut().enumerate() {
        *bit = ((packed >> (idx * BIT_COUNT)) & mask).as_u32() as u8;
    }
    debug_assert_eq!(pack::<F>(&bits), packed.to_scalar().unwrap());
    bits
}

/// Pack bits stored in a u64 value into a sparse keccak word
pub fn pack_u64<F: Field>(value: u64) -> F {
    pack(&((0..NUM_BITS_PER_WORD).map(|i| ((value >> i) & 1) as u8).collect::<Vec<_>>()))
}

/// Calculates a ^ b with a and b field elements
pub fn field_xor<F: Field>(a: F, b: F) -> F {
    let mut bytes = [0u8; 32];
    for (idx, (a, b)) in a.to_bytes_le().into_iter().zip(b.to_bytes_le()).enumerate() {
        bytes[idx] = a ^ b;
    }
    F::from_bytes_le(&bytes)
}

/// Returns the size (in bits) of each part size when splitting up a keccak word
/// in parts of `part_size`
pub fn target_part_sizes(part_size: usize) -> Vec<usize> {
    let num_full_chunks = NUM_BITS_PER_WORD / part_size;
    let partial_chunk_size = NUM_BITS_PER_WORD % part_size;
    let mut part_sizes = vec![part_size; num_full_chunks];
    if partial_chunk_size > 0 {
        part_sizes.push(partial_chunk_size);
    }
    part_sizes
}

/// Gets the rotation count in parts
pub fn get_rotate_count(count: usize, part_size: usize) -> usize {
    (count + part_size - 1) / part_size
}

/// Encodes the data using rlc
pub mod compose_rlc {
    use halo2_proofs::plonk::Expression;

    use crate::util::eth_types::Field;

    #[allow(dead_code)]
    pub(crate) fn expr<F: Field>(expressions: &[Expression<F>], r: F) -> Expression<F> {
        let mut rlc = expressions[0].clone();
        let mut multiplier = r;
        for expression in expressions[1..].iter() {
            rlc = rlc + expression.clone() * multiplier;
            multiplier *= r;
        }
        rlc
    }
}

/// Packs bits into bytes
pub mod to_bytes {
    pub fn value(bits: &[u8]) -> Vec<u8> {
        debug_assert!(bits.len() % 8 == 0, "bits not a multiple of 8");
        let mut bytes = Vec::new();
        for byte_bits in bits.chunks(8) {
            let mut value = 0u8;
            for (idx, bit) in byte_bits.iter().enumerate() {
                value += *bit << idx;
            }
            bytes.push(value);
        }
        bytes
    }
}

/// Scatters a value into a packed word constant
pub mod scatter {
    use halo2_proofs::plonk::Expression;

    use crate::util::eth_types::Field;

    use super::pack;

    pub(crate) fn expr<F: Field>(value: u8, count: usize) -> Expression<F> {
        Expression::Constant(pack(&vec![value; count]))
    }
}
