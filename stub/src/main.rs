use std::io::Read;

use bincode::{
    config::{self},
    Decode,
};
use libnanomite::{from_option_bytes, read::ZlibDecoder, EncryptedObject, JumpDataTable};
use stub::runtime_main;

fn get_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let (config, offset) = from_option_bytes(bytes)?;
    let bytes = &bytes[offset..];

    let bytes = if config.encrypted {
        let encrypted_obj: EncryptedObject = bincode::decode_from_slice(bytes, config::standard())
            .ok()?
            .0;
        encrypted_obj.try_into().ok()?
    } else {
        bytes.to_vec()
    };

    let bytes = if config.compressed {
        let mut decoder = ZlibDecoder::new(bytes.as_slice());
        let mut v = Vec::new();
        decoder.read_to_end(&mut v).ok()?;

        v
    } else {
        bytes
    };

    Some(bytes)
}

fn get_bin(bytes: &[u8]) -> Option<Vec<u8>> {
    get_bytes(bytes)
}

fn get_jdt(bytes: &[u8]) -> Option<JumpDataTable> {
    let bytes = get_bytes(bytes)?;
    let jdt: JumpDataTable = bincode::decode_from_slice(bytes.as_slice(), config::standard())
        .ok()?
        .0;

    Some(jdt)
}

fn main() {
    let bin = include_bytes!(env!("NANOSTORM_BIN"));
    let jdt = include_bytes!(env!("NANOSTORM_JDT"));

    let bin = get_bin(bin).unwrap();
    let jdt = get_jdt(jdt).unwrap();

    runtime_main(&bin, jdt);
}
