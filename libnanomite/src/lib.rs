#![no_std]

use aead::{Aead, OsRng};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use alloc::vec::Vec;
use bincode::{config, Decode, Encode};
use hashbrown::HashMap;
extern crate alloc;

#[derive(Encode, Decode, Copy, Clone)]
pub enum JumpType {
    Jo,
    Jno,
    Js,
    Jns,
    Jz,
    Jnz,
    Jb,
    Jnb,
    Jbe,
    Ja,
    Jl,
    Jge,
    Jle,
    Jg,
    Jp,
    Jnp,
    Jcxz,
}

#[derive(Encode, Decode, Copy, Clone)]
pub struct JumpData {
    jump_type: JumpType,
    j_false: u8,
    j_true: isize,
}

impl JumpData {
    pub fn new(jump_type: JumpType, size: u8, offset: isize) -> Self {
        Self {
            jump_type,
            j_false: size,
            j_true: offset,
        }
    }

    pub fn eval_jump(&self, eflags: usize, rcx: usize) -> isize {
        // todo check this
        if match self.jump_type {
            JumpType::Jo => eflags & (1 << 11) != 0,
            JumpType::Jno => eflags & (1 << 11) == 0,
            JumpType::Js => eflags & (1 << 7) != 0,
            JumpType::Jns => eflags & (1 << 7) == 0,
            JumpType::Jz => eflags & (1 << 6) != 0,
            JumpType::Jnz => eflags & (1 << 6) == 0,
            JumpType::Jb => eflags & (1 << 0) != 0,
            JumpType::Jnb => eflags & (1 << 0) == 0,
            JumpType::Jbe => eflags & (1 << 0) != 0 || eflags & (1 << 6) != 0,
            JumpType::Ja => eflags & (1 << 0) == 0 && eflags & (1 << 6) == 0,
            JumpType::Jl => eflags & (1 << 11) != eflags & (1 << 7),
            JumpType::Jge => eflags & (1 << 11) == eflags & (1 << 7),
            JumpType::Jle => eflags & (1 << 11) != eflags & (1 << 7) || eflags & (1 << 6) != 0,
            JumpType::Jg => eflags & (1 << 11) == eflags & (1 << 7) && eflags & (1 << 6) == 0,
            JumpType::Jp => eflags & (1 << 2) != 0,
            JumpType::Jnp => eflags & (1 << 2) == 0,
            JumpType::Jcxz => rcx == 0,
        } {
            self.j_true
        } else {
            self.j_false as isize
        }
    }
}

pub type VirtAddr = usize;

pub struct JumpDataTable {
    table: HashMap<VirtAddr, JumpData>,
}

impl Decode for JumpDataTable {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let vec = Vec::<(VirtAddr, JumpData)>::decode(decoder)?;
        let mut hashmap = HashMap::new();

        for (key, value) in vec {
            hashmap.insert(key, value);
        }

        Ok(Self { table: hashmap })
    }
}

impl Encode for JumpDataTable {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        let mut vec = Vec::new();
        for (addr, data) in self.table.iter() {
            vec.push((*addr, *data));
        }
        vec.encode(encoder)
    }
}

impl JumpDataTable {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    pub fn insert(&mut self, vaddr: VirtAddr, jump_data: JumpData) {
        self.table.insert(vaddr, jump_data);
    }

    pub fn get(&self, vaddr: VirtAddr) -> Option<&JumpData> {
        self.table.get(&vaddr)
    }
}

const AES_GCM_NONCE: &[u8] = "nanomites:^)".as_bytes();

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
