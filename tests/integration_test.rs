use std::collections::HashMap;
use std::process::Command;
use std::sync::Once;

static INIT: Once = Once::new();
const ASSETS_PATH: &str = "out";

// This function should run `cargo run --bin gen-keys` to generate the proving and verifying keys.
fn setup_keys() {
    INIT.call_once(|| {
        let mut gen_keys_command = Command::new("cargo");
        gen_keys_command
            .arg("run")
            .arg("--bin")
            .arg("gen-keys");

        gen_keys_command
            .spawn()
            .expect("Failed to spawn cargo build")
            .wait()
            .expect("cargo build errored");
    });
}


#[test]
fn test_prove_verify_end_to_end() {
    setup_keys();

    let input = [1u8, 10u8, 100u8].repeat(10);

    let mut inputs = HashMap::new();

    inputs.insert(
        "in".to_string(),
        input
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>(),
    );

    let proving_key_path = format!("{}/keccak256_pk", ASSETS_PATH);
    let verifying_key_path = format!("{}/keccak256_vk", ASSETS_PATH);
    let srs_key_path = format!("{}/keccak256_srs", ASSETS_PATH);

    let result = halo2_keccak_256::prove(&srs_key_path, &proving_key_path, inputs).unwrap();
    let verified = halo2_keccak_256::verify(
        &srs_key_path,
        &verifying_key_path,
        result.0,
        result.1,
    )
        .unwrap();
    assert!(verified);
}