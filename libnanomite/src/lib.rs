#![no_std]

mod jump_type;
mod jump_data;
mod jdt;
mod encrypted_jdt;

pub use jump_type::JumpType;
pub use jump_data::JumpData;
pub use jdt::JumpDataTable;
pub use encrypted_jdt::EncryptedJumpDataTable;

extern crate alloc;

pub type VirtAddr = usize;

const AES_GCM_NONCE: &[u8] = "nanomites:^)".as_bytes();

