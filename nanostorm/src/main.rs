#[macro_use]
mod log;
mod ghidra_runner;
mod vaddr_lookup;

use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use color_eyre::{eyre::Context, owo_colors::OwoColorize};
use ghidra_runner::InstrLocations;
use goblin::Object;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use rayon::prelude::*;
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
    let vaddr_lookup = create_vaddr_lookup(&buffer)?;

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
    let mut decoder = Decoder::new(64, &buffer, DecoderOptions::NONE);

    for (vaddr, offset) in offsets {
        decoder.set_position(*offset)?;
        decoder.set_ip(*vaddr as u64);

        let instr = decoder.decode();

        // ensure the instruction is a conditional branch, but not a loop
        if instr.flow_control() == FlowControl::ConditionalBranch && !instr.is_loopcc() {
            place_nanomite(&mut buffer, *offset, &instr)?;
        } else if *&buffer[*offset..*offset + instr.len()].contains(&0xCC) {
            info!("Found breakpoint at offset: {:x}", offset);
            place_fake_nanomite(&mut buffer, *offset)?;
        }
    }

    Ok(())
}

fn place_fake_nanomite(buffer: &mut &mut [u8], offset: usize) -> _ {
    todo!()
}

fn place_nanomite(buffer: &mut [u8], offset: usize, instr: &Instruction) -> _ {
    todo!()    
}
