#[macro_use]
mod log;
mod ghidra_runner;
mod vaddr_lookup;

use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use color_eyre::{eyre::Context, owo_colors::OwoColorize};
use ghidra_runner::InstrLocations;
use goblin::Object;
use iced_x86::code_asm::CodeAssembler;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, NasmFormatter,
};
use libnanomite::{JumpData, JumpDataTable, JumpType, VirtAddr};
use rand::random;
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
    info!("Ghidra reported {} instructions", instrs.len());
    let offsets = get_offsets(buffer, instrs)?;

    info!("Found {} instructions", offsets.len());
    process_instructions(buffer, &offsets)?;

    Ok(())
}

fn get_offsets(buffer: &mut [u8], instrs: &Vec<usize>) -> Result<Vec<(VirtAddr, usize)>> {
    let vaddr_lookup = create_vaddr_lookup(buffer)?;
    let offsets: Vec<(usize, usize)> = instrs
        .into_par_iter()
        .filter_map(|vaddr| {
            vaddr_lookup
                .virtual_address(*vaddr)
                .ok()
                .map(|o| (*vaddr, o))
        })
        .collect();
    Ok(offsets)
}

fn process_instructions(buffer: &mut [u8], offsets: &[(usize, usize)]) -> Result<()> {
    // Since we're modifying the buffer by placing nanomites, create a copy so we can
    // decode correctly.
    let buf_copy = buffer.to_owned();
    let mut decoder = Decoder::new(64, &buf_copy, DecoderOptions::NONE);

    let mut formatter = NasmFormatter::new();
    let mut output = String::new();

    formatter.options_mut().set_digit_separator("`");
    formatter.options_mut().set_first_operand_char_index(10);

    let mut instr = Instruction::default();

    let mut jdt = JumpDataTable::new();

    for (vaddr, offset) in offsets {
        decoder.set_position(*offset)?;
        decoder.set_ip(*vaddr as u64);

        decoder.decode_out(&mut instr);

        output.clear();
        formatter.format(&instr, &mut output);

        // ensure the instruction is a conditional branch, but not a loop
        let mut nanomite = None;

        // TODO: add nanomites for jmp rel8/16/32
        if instr.flow_control() == FlowControl::ConditionalBranch
            && !instr.is_loopcc()
            && !instr.is_loop()
        {
            nanomite = Some(place_nanomite(buffer, *offset, &instr)?);
            info!("nanomite: {:X} {}", *vaddr, output);
        } else if buffer[*offset..*offset + instr.len()].contains(&0xCC) {
            nanomite = Some(place_fake_nanomite()?);
            warning!("fake nanomite: {:X} {}", *vaddr, output);
        }

        if let Some(n) = nanomite {
            jdt.insert(*vaddr, n);
        }
    }

    Ok(())
}

fn place_fake_nanomite() -> Result<JumpData> {
    // create a real jcc instruction, and then encode it.
    let jump_type: JumpType = random();

    let mut asm = CodeAssembler::new(64)?;
    let target = random::<u64>() % i8::MAX as u64;

    match jump_type {
        JumpType::Ja => asm.ja(target)?,
        JumpType::Jae => asm.jae(target)?,
        JumpType::Jb => asm.jb(target)?,
        JumpType::Jbe => asm.jbe(target)?,
        JumpType::Jcxz => asm.jcxz(target)?,
        JumpType::Je => asm.je(target)?,
        JumpType::Jecxz => asm.jecxz(target)?,
        JumpType::Jg => asm.jg(target)?,
        JumpType::Jge => asm.jge(target)?,
        JumpType::Jl => asm.jl(target)?,
        JumpType::Jle => asm.jle(target)?,
        JumpType::Jmp => asm.jmp(target)?,
        JumpType::Jmpe => asm.jmpe(target)?,
        JumpType::Jne => asm.jne(target)?,
        JumpType::Jno => asm.jno(target)?,
        JumpType::Jnp => asm.jnp(target)?,
        JumpType::Jns => asm.jns(target)?,
        JumpType::Jo => asm.jo(target)?,
        JumpType::Jp => asm.jp(target)?,
        JumpType::Jrcxz => asm.jrcxz(target)?,
        JumpType::Js => asm.js(target)?,
    };

    let bytes = asm.assemble(0x0)?;
    let jd = JumpData::new(jump_type, bytes.len() as u8, target as isize);

    warning!("fake nanomite: {:?}", jd);
    Ok(jd)
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
        instr.near_branch64().wrapping_sub(instr.ip()) as isize,
    );

    info!("nanomite: {:?}", nanomite);

    // Place the nanomite
    buffer[offset] = 0xcc;

    // Replace rest of bytes with garbage
    for i in 1..instr.len() {
        buffer[offset + i] = random();
    }

    Ok(nanomite)
}
