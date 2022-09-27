use aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Nonce};
use alloc::vec::Vec;
use bincode::config;

use crate::{jdt::JumpDataTable, AES_GCM_NONCE};

pub struct EncryptedJumpDataTable {
    key: [u8; 16],
    encrypted_table: Vec<u8>,
}

impl From<JumpDataTable> for EncryptedJumpDataTable {
    fn from(jdt: JumpDataTable) -> Self {
        let serialized = bincode::encode_to_vec(jdt, config::standard())
            .expect("failed to serialize jump data table");

        let key = Aes128Gcm::generate_key(&mut OsRng);
        let nonce = Nonce::from_slice(AES_GCM_NONCE);
        let cipher = Aes128Gcm::new(&key);

        let ciphertext = cipher.encrypt(nonce, serialized.as_slice()).unwrap();

        Self {
            key: key.into(),
            encrypted_table: ciphertext,
        }
    }
}

impl From<EncryptedJumpDataTable> for JumpDataTable {
    fn from(ejdt: EncryptedJumpDataTable) -> Self {
        let nonce = Nonce::from_slice(AES_GCM_NONCE);
        let cipher = Aes128Gcm::new(&ejdt.key.into());

        let plaintext = cipher
            .decrypt(nonce, ejdt.encrypted_table.as_slice())
            .unwrap();

        let jdt = bincode::decode_from_slice(plaintext.as_slice(), config::standard())
            .expect("failed to decrypt jdt")
            .0;
        jdt
    }
}
