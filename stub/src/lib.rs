// #![no_std]
extern crate alloc;

mod backends;

#[cfg(target_os = "linux")]
use backends::linux;

#[cfg(target_os = "windows")]
use backends::windows;

use libnanomite::JumpDataTable;

pub fn runtime_main(bin: &[u8], jdt: JumpDataTable) {
    #[cfg(target_os = "linux")]
    linux::run(bin, jdt);

    #[cfg(target_os = "windows")]
    windows::run(bin, jdt);

    // regex to match any base64 encoded string
    // let re = Regex::new(r"([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?").unwrap();
}
