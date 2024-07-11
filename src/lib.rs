//! The zkEVM keccak circuit implementation, with some modifications.
//! Credit goes to https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit
//!
//! This is a lookup table based implementation, where bytes are packed into big field elements as efficiently as possible.
//! The circuits can be configured to use different numbers of columns, by specifying the number of rows per internal
//! round of the keccak_f permutation.

/// Module for Keccak circuits in vanilla halo2.
mod vanilla;
mod util;

mod circuit;
pub mod io;

use std::collections::HashMap;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::ProvingKey;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
pub use circuit::KeccakCircuit;
pub use vanilla::KeccakConfigParams;
use crate::circuit::unpack_input;

pub const DEFAULT_ROWS_PER_ROUND: usize = 28;
pub const DEFAULT_K: u32 = 14;

#[cfg(test)]
mod tests;
