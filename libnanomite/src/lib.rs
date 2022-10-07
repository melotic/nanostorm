#![no_std]
mod encrypted_jdt;
mod jdt;
mod jump_data;
mod jump_type;

pub use encrypted_jdt::EncryptedJumpDataTable;
pub use jdt::JumpDataTable;
pub use jump_data::JumpData;
pub use jump_type::JumpType;

extern crate alloc;

pub type VirtAddr = usize;

const AES_GCM_NONCE: &[u8] = "nanomites:^)".as_bytes();
