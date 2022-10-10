#![no_std]

use bincode::config::{self};
use stub::runtime_main;

fn main() {
    let bin = include_bytes!(env!("NANOSTORM_BIN"));
    let jdt = include_bytes!(env!("NANOSTORM_JDT"));

    let jdt = bincode::decode_from_slice(jdt, config::standard())
        .unwrap()
        .0;

    runtime_main(bin, jdt);
}
