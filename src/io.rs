use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Write};
use std::path::Path;

use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::{Circuit, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::SerdeFormat::RawBytes;

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

/// Read SRS from
pub fn read_srs_bytes(data: &[u8]) -> ParamsKZG<Bn256> {
    ParamsKZG::read::<_>(&mut &data[..]).unwrap()
}

/// Read a proving key from the file.
pub fn read_pk<C: Circuit<Fr>>(path: &Path, params: C::Params) -> ProvingKey<G1Affine> {
    with_reader(path, |reader| {
        ProvingKey::read::<_, C>(reader, RawBytes, params)
    })
}

/// Read a proving key from raw data.
pub fn read_pk_bytes<C: Circuit<Fr>>(bytes: &[u8], params: C::Params) -> ProvingKey<G1Affine> {
    let mut cursor = Cursor::new(bytes);
    ProvingKey::read::<_, C>(&mut cursor, RawBytes, params).unwrap()
}

/// Read a verification key from the file.
pub fn read_vk<C: Circuit<Fr>>(path: &Path, params: C::Params) -> VerifyingKey<G1Affine> {
    with_reader(path, |reader| {
        VerifyingKey::read::<_, C>(reader, RawBytes, params)
    })
}

/// Read a verification key from raw data.
pub fn read_vk_bytes<C: Circuit<Fr>>(bytes: &[u8], params: C::Params) -> VerifyingKey<G1Affine> {
    let mut cursor = Cursor::new(bytes);
    VerifyingKey::read::<_, C>(&mut cursor, RawBytes, params).unwrap()
}
