use clap::{App, Arg};
use std::env;
use std::path::Path;

use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::plonk::{keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use halo2_keccak_256::{DEFAULT_K, DEFAULT_ROWS_PER_ROUND, KeccakCircuit, KeccakConfigParams};
use halo2_keccak_256::io::{write_keys, write_srs};

pub fn main() {
    // Setup command-line argument parsing
    let matches = App::new("Keccak Keys Generator")
        .about("Generates keys for the Keccak circuit")
        .arg(Arg::with_name("k")
            .long("k")
            .short('k')
            .help("Size of the circuit to allocate")
            .takes_value(true)
            .default_value(&DEFAULT_K.to_string()))
        .arg(Arg::with_name("rows-per-round")
            .long("rows-per-round")
            .short('r')
            .help("Amount of row compression in the circuit")
            .takes_value(true)
            .default_value(&DEFAULT_ROWS_PER_ROUND.to_string()))
        .get_matches();

    println!("{}", format!("Generating keys for Keccak circuit with k = {} and rows-per-round = {}", matches.value_of("k").unwrap(), matches.value_of("rows-per-round").unwrap()));

    let k = matches.value_of("k").unwrap().parse::<u32>().expect("Invalid value for -k");
    let rows_per_round = matches.value_of("rows-per-round").unwrap().parse::<usize>().expect("Invalid value for -r");

    let project_root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
    let out_dir = Path::new(&project_root).join("out");

    if !out_dir.exists() {
        std::fs::create_dir(&out_dir).expect("Unable to create out directory");
    }

    let circuit_name = "keccak256";
    let circuit = KeccakCircuit::new(
        KeccakConfigParams {
            k,
            rows_per_round,
        },
        Some(2usize.pow(k)),
        vec![],
        false,
        false,
    );

    let srs = ParamsKZG::<Bn256>::new(k);
    let srs_path = out_dir.join(format!("{}_srs", circuit_name));
    write_srs(&srs, srs_path.as_path());

    let vk = keygen_vk(&srs, &circuit).expect("keygen_vk should not fail");
    let vk_path = out_dir.join(format!("{}_vk", circuit_name));
    let pk = keygen_pk(&srs, vk, &circuit).expect("keygen_pk should not fail");
    let pk_path = out_dir.join(format!("{}_pk", circuit_name));

    write_keys(&pk, pk_path.as_path(), vk_path.as_path());

    println!("Circuit file preparation finished successfully.");
    println!("SRS stored in {}", srs_path.display());
    println!("Proving key stored in {}", pk_path.display());
    println!("Verification key stored in {}", vk_path.display());
}