use std::{fmt, io};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::SerdeFormat::RawBytes;
use crate::KeccakCircuit;
use crate::vanilla::KeccakConfigParams;

fn with_writer<E>(path: &Path, f: impl FnOnce(&mut BufWriter<File>) -> Result<(), E>)
where
    E: fmt::Debug,
{
    let file = File::create(path).expect("Unable to create file");
    let mut writer = BufWriter::new(file);
    f(&mut writer).expect("Unable to write to file");
    writer.flush().expect("Unable to flush file");
}

fn with_reader<T, E>(path: &Path, f: impl FnOnce(&mut BufReader<File>) -> Result<T, E>) -> T
where
    E: fmt::Debug,
{
    let file = File::open(path).expect("Unable to open file");
    let mut reader = BufReader::new(file);
    f(&mut reader).expect("Unable to read from file")
}

/// Write SRS to file.
pub fn write_srs(srs: &ParamsKZG<Bn256>, path: &Path) {
    with_writer(path, |writer| srs.write(writer));
}

/// Write proving key and verification key to file.
pub fn write_keys(pk: &ProvingKey<G1Affine>, pk_path: &Path, vk_path: &Path) {
    with_writer(pk_path, |writer| pk.write(writer, RawBytes));
    with_writer(vk_path, |writer| pk.get_vk().write(writer, RawBytes));
}

/// Read SRS from file.
pub fn read_srs_path(path: &Path) -> ParamsKZG<Bn256> {
    with_reader(path, |reader| ParamsKZG::read(reader))
}

/// Read a proving key from the file.
pub fn read_pk<R: Read>(reader: &mut R, params: KeccakConfigParams) -> io::Result<ProvingKey<G1Affine>> {
    ProvingKey::read::<_, KeccakCircuit<_>>(reader, RawBytes, params)
}

/// Read a verification key from the file.
pub fn read_vk<R: Read>(reader: &mut R, params: KeccakConfigParams) -> io::Result<VerifyingKey<G1Affine>> {
    VerifyingKey::read::<_, KeccakCircuit<_>>(reader, RawBytes, params)
}