//! The zkEVM keccak circuit implementation, with some modifications.
//! Credit goes to https://github.com/privacy-scaling-explorations/zkevm-circuits/tree/main/zkevm-circuits/src/keccak_circuit
//!
//! This is a lookup table based implementation, where bytes are packed into big field elements as efficiently as possible.
//! The circuits can be configured to use different numbers of columns, by specifying the number of rows per internal
//! round of the keccak_f permutation.

use std::collections::HashMap;
use std::fmt::Display;
use std::path::Path;
use halo2_proofs::halo2curves::bn256::Fr;
use thiserror::Error;
pub use circuit::{KeccakCircuit};
pub use vanilla::KeccakConfigParams;
use crate::circuit::{generate_halo2_proof, verify_halo2_proof};
use crate::serialisation::{deserialize_circuit_inputs, InputsSerialisationWrapper};

/// Module for Keccak circuits in vanilla halo2.
mod vanilla;
mod util;

mod circuit;
pub mod io;

#[cfg(test)]
mod tests;
mod serialisation;

pub const DEFAULT_CONFIG : KeccakConfigParams = KeccakConfigParams {
    k: 14,
    rows_per_round: 28,
};

#[derive(Debug, Error)]
pub struct Keccak256Error(String);

impl Display for Keccak256Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub fn prove(
    srs_key_path: &str,
    proving_key_path: &str,
    input: HashMap<String, Vec<String>>,
) -> Result<(Vec<u8>, Vec<u8>), Keccak256Error> {
    let circuit_inputs = deserialize_circuit_inputs(input).map_err(|e| {
        Keccak256Error(format!("Failed to deserialize circuit inputs: {}", e))
    })?;

    let srs = io::read_srs_path(Path::new(&srs_key_path));

    let circuit_config = DEFAULT_CONFIG;

    let proving_key = io::read_pk::<KeccakCircuit<Fr>>(
        Path::new(&proving_key_path),
        circuit_config,
    );

    let (inputs, proof) =
        generate_halo2_proof(circuit_inputs, &srs, &proving_key, Some(circuit_config))
            .map_err(|e| {
                Keccak256Error(format!("Failed to generate the proof: {}", e))
            })?;

    let serialized_inputs =
        bincode::serialize(&InputsSerialisationWrapper(inputs)).map_err(|e| {
            Keccak256Error(format!("Serialisation of Inputs failed: {}", e))
        })?;

    Ok((
        proof,
        serialized_inputs,
    ))
}

pub fn verify(
    srs_key_path: &str,
    verifying_key_path: &str,
    proof: Vec<u8>,
    public_inputs: Vec<u8>,
) -> Result<bool, Keccak256Error> {
    let deserialized_inputs = bincode::deserialize::<InputsSerialisationWrapper>(&public_inputs)
        .map_err(|e| Keccak256Error(e.to_string()))?.0;

    let circuit_config = DEFAULT_CONFIG;

    let srs = io::read_srs_path(Path::new(&srs_key_path));

    let verifying_key = io::read_vk::<KeccakCircuit<Fr>>(
        Path::new(&verifying_key_path),
        circuit_config,
    );

    let is_valid =
        verify_halo2_proof(proof, &deserialized_inputs, &srs, &verifying_key).unwrap();

    Ok(is_valid)
}




