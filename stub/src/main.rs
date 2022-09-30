#![no_std]

use bincode::config::{self, Config};
use stub::runtime_main;

fn main() {
    let bin = include_bytes!("../../infected.bin");
    let jdt = include_bytes!("../../jdt.bin");

    let jdt = bincode::decode_from_slice(jdt, config::standard())
        .unwrap()
        .0;

    runtime_main(bin, jdt);
}
