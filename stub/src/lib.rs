// #![no_std]
extern crate alloc;

mod backends;

use backends::{linux, windows};
use libnanomite::JumpDataTable;

pub fn runtime_main(bin: &[u8], jdt: JumpDataTable) {
    if cfg!(target_os = "linux") {
        linux::run(bin, jdt);
    } else if cfg!(target_os = "windows") {
        windows::run(bin, jdt);
    } else {
        panic!("Unsupported OS");
    }
}
