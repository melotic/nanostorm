#[macro_use]
mod log;
mod ghidra_runner;
mod vaddr_lookup;

use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use color_eyre::{eyre::Context, owo_colors::OwoColorize};
use ghidra_runner::InstrLocations;
use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
use libnanomite::{JumpData, JumpType};
use rayon::prelude::*;
use std::mem;
use std::{
    fs::{self},
    path::{Path, PathBuf},
};
use vaddr_lookup::VirtualAddressor;

use crate::ghidra_runner::run_ghidra_disassembly;
use crate::vaddr_lookup::{ElfVirtualAddressor, PeVirtualAddressor};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, long)]
    ghidra_path: PathBuf,

    #[clap()]
    binary: PathBuf,

    #[clap(short, long)]
    output: Option<String>,
}

#[derive(Debug)]
struct ParsedArgs {
    ghidra_path: PathBuf,
    binary: PathBuf,
    output: String,
}

impl From<Args> for ParsedArgs {
    fn from(args: Args) -> Self {
        let output = match args.output {
            Some(o) => o,
            None => args
                .binary
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string(),
        };
        ParsedArgs {
            ghidra_path: args.ghidra_path,
            binary: args.binary,
            output,
        }
    }
}

fn find_headless_ghidra(ghidra_path: &Path) -> Result<PathBuf> {
    let bin_name = if cfg!(target_os = "windows") {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    };

    let ghidra_headless = ghidra_path.join("support").join(bin_name);

    if !ghidra_headless.exists() {
        Err(eyre!(
            "analyzeHeadless not found. Did you specify the correct Ghidra path?"
        ))
    } else {
        success!("Ghidra headless path: {:?}", ghidra_headless);
        Ok(ghidra_headless)
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = ParsedArgs::from(Args::parse());
    let mut buffer = fs::read(&cli.binary)
        .wrap_err_with(|| format!("Could not read {}", cli.binary.display()))?;
    let intrs = run_ghidra_disassembly(&find_headless_ghidra(&cli.ghidra_path)?, &cli.binary)?;

    process_binary(&mut buffer, &intrs, &cli.output)?;

    Ok(())
}

fn create_vaddr_lookup<'a>(buffer: &'a [u8]) -> Result<Box<dyn VirtualAddressor + Sync + 'a>> {
    let obj = Object::parse(buffer).wrap_err_with(|| "Error parsing the binary file.")?;

    match obj {
        Object::Elf(elf) => Ok(Box::new(ElfVirtualAddressor::new(elf))),
        Object::PE(pe) => Ok(Box::new(PeVirtualAddressor::new(pe))),
        _ => Err(eyre!("Could not parse binary as a PE or ELF file.",)),
    }
}

fn process_binary<'a>(
    buffer: &'a mut [u8],
    instrs: &'a InstrLocations,
    _output: &str,
) -> Result<()> {
    // map all instrs to their offsets in the binary
    let vaddr_lookup = create_vaddr_lookup(buffer)?;

    let offsets: Vec<(usize, usize)> = instrs
        .into_par_iter()
        .filter_map(|vaddr| {
            vaddr_lookup
                .virtual_address(*vaddr)
                .ok()
                .map(|o| (o, *vaddr))
        })
        .collect();

    info!("Found {} instructions", offsets.len());
    process_instructions(buffer, &offsets)?;

    Ok(())
}

fn process_instructions(buffer: &mut [u8], offsets: &[(usize, usize)]) -> Result<()> {
    let mut decoder = Decoder::new(64, buffer, DecoderOptions::NONE);

    for (vaddr, offset) in offsets {
        decoder.set_position(*offset)?;
        decoder.set_ip(*vaddr as u64);

        let instr = decoder.decode();

        // ensure the instruction is a conditional branch, but not a loop
        let mut nanomite = None;

        if instr.flow_control() == FlowControl::ConditionalBranch && !instr.is_loopcc() {
            nanomite = Some(place_nanomite(buffer, *offset, &instr)?);
        } else if *&buffer[*offset..*offset + instr.len()].contains(&0xCC) {
            info!("Found breakpoint at offset: {:x}", offset);
            nanomite = Some(place_fake_nanomite());
        }
    }

    Ok(())
}

fn place_fake_nanomite() -> JumpData {
    // generate random jump type
    let jump_type = rand::random::<JumpType>();
    let target = rand::random::<u32>() as usize;

    let mut zero_bytes = 0;
    for i in 0..mem::size_of::<u32>() {
        if target & (0xFF << (i * 8)) == 0 {
            zero_bytes += 1;
        } else {
            break;
        }
    }

    let size = rand::random::<usize>() % (mem::size_of::<u32>() - zero_bytes) + 1;

    JumpData::new(jump_type, size as u8, size as isize)
}

fn convert_jump_type(mnemonic: Mnemonic) -> Result<JumpType> {
    match mnemonic {
        Mnemonic::Ja => Ok(JumpType::Ja),
        Mnemonic::Jae => Ok(JumpType::Jae),
        Mnemonic::Jb => Ok(JumpType::Jb),
        Mnemonic::Jbe => Ok(JumpType::Jbe),
        Mnemonic::Jcxz => Ok(JumpType::Jcxz),
        Mnemonic::Je => Ok(JumpType::Je),
        Mnemonic::Jecxz => Ok(JumpType::Jecxz),
        Mnemonic::Jg => Ok(JumpType::Jg),
        Mnemonic::Jge => Ok(JumpType::Jge),
        Mnemonic::Jl => Ok(JumpType::Jl),
        Mnemonic::Jle => Ok(JumpType::Jle),
        Mnemonic::Jmp => Ok(JumpType::Jmp),
        Mnemonic::Jmpe => Ok(JumpType::Jmpe),
        Mnemonic::Jne => Ok(JumpType::Jne),
        Mnemonic::Jno => Ok(JumpType::Jno),
        Mnemonic::Jnp => Ok(JumpType::Jnp),
        Mnemonic::Jns => Ok(JumpType::Jns),
        Mnemonic::Jo => Ok(JumpType::Jo),
        Mnemonic::Jp => Ok(JumpType::Jp),
        Mnemonic::Jrcxz => Ok(JumpType::Jrcxz),
        Mnemonic::Js => Ok(JumpType::Js),
        _ => Err(eyre!("Invalid jump type: {:?}", mnemonic)),
    }
}
fn place_nanomite(buffer: &mut [u8], offset: usize, instr: &Instruction) -> Result<JumpData> {
    // Create the nanomite
    let nanomite = JumpData::new(
        convert_jump_type(instr.mnemonic())?,
        instr.len() as u8,
        instr.near_branch64() as isize,
    );

    // Place the nanomite
    buffer[offset] = 0xcc;

    // Replace rest of bytes with garbage
    for i in 1..instr.len() {
        buffer[offset + i] = rand::random();
    }

    Ok(nanomite)
}
