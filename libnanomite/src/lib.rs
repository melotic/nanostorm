#![no_std]
pub mod cereal;
mod encrypted_jdt;
mod encrypted_object;
mod jdt;
mod jump_data;
mod jump_type;

pub use encrypted_jdt::EncryptedJumpDataTable;
pub use encrypted_object::EncryptedObject;
pub use jdt::JumpDataTable;
pub use jump_data::JumpData;
pub use jump_type::JumpType;
extern crate alloc;

pub type VirtAddr = usize;

const AES_GCM_NONCE: &[u8] = "nanomites:^)".as_bytes();
const CONFIG_BYTES: usize = 2;

const ENCRPYT_OFFSET: usize = 0;
const COMPRESS_OFFSET: usize = 1;

pub struct Config {
    pub encrypted: bool,
    pub compressed: bool,
}

/// Encodes the options that the JDT or the Binary is encrypted and compress. This is read by the stub to determine if the binary should be decompressed and decrypted.
pub fn to_option_bytes(encrypt: bool, compress: bool) -> [u8; CONFIG_BYTES] {
    let mut v = [0; CONFIG_BYTES];
    v[ENCRPYT_OFFSET] = encrypt as u8;
    v[COMPRESS_OFFSET] = compress as u8;

    assert!(v.len() == CONFIG_BYTES);

    v
}

/// Decodes the options that the JDT or the Binary is encrypted and compressed. This is read by the stub to determine if the binary should be decompressed and decrypted.
/// This returns a tuple of (encrypt, compress), and a usize indicating the number of bytes the options take up to compute the start of the JDT or Binary.
pub const fn from_option_bytes(bytes: &[u8]) -> Option<(Config, usize)> {
    if bytes.len() < CONFIG_BYTES {
        return None;
    }

    let options = Config {
        encrypted: bytes[ENCRPYT_OFFSET] != 0,
        compressed: bytes[COMPRESS_OFFSET] != 0,
    };

    Some((options, CONFIG_BYTES))
}
