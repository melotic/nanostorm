use aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes128Gcm, Nonce};
use alloc::vec::Vec;
use bincode::{config, Decode, Encode};

use crate::AES_GCM_NONCE;

#[derive(Decode, Encode)]
pub struct EncryptedObject {
    key: [u8; 16],
    ciphertext: Vec<u8>,
}

impl TryFrom<&[u8]> for EncryptedObject {
    type Error = aead::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let key = Aes128Gcm::generate_key(&mut OsRng);
        let cipher = Aes128Gcm::new(&key);

        let ciphertext = cipher.encrypt(Nonce::from_slice(AES_GCM_NONCE), value)?;

        Ok(Self {
            key: key.into(),
            ciphertext,
        })
    }
}

impl TryInto<Vec<u8>> for EncryptedObject {
    type Error = aead::Error;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let cipher = Aes128Gcm::new(&self.key.into());
        let plaintext =
            cipher.decrypt(Nonce::from_slice(AES_GCM_NONCE), self.ciphertext.as_ref())?;

        Ok(plaintext)
    }
}

impl EncryptedObject {
    pub fn decode<T: Decode>(self) -> Result<T, ()> {
        let plaintext: Vec<u8> = self.try_into().map_err(|_| ())?;
        Ok(
            bincode::decode_from_slice(plaintext.as_slice(), config::standard())
                .map_err(|_| ())?
                .0,
        )
    }
}
