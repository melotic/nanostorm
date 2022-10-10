#[macro_use]
mod log;
mod cli;
mod ghidra_runner;
mod vaddr_lookup;

use crate::ghidra_runner::run_ghidra_disassembly;
use crate::vaddr_lookup::{ElfVirtualAddressor, PeVirtualAddressor};
use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use color_eyre::{eyre::Context, owo_colors::OwoColorize};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use ghidra_runner::{find_headless_ghidra, InstrLocations};
use goblin::Object;
use iced_x86::code_asm::CodeAssembler;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, Mnemonic, NasmFormatter,
};
use libnanomite::cereal::config;
use libnanomite::{
    cereal, to_option_bytes, EncryptedObject, JumpData, JumpDataTable, JumpType, VirtAddr,
};
use rand::random;
use rayon::prelude::*;
use std::cmp::max;
use std::fs;
use std::fs::File;
use std::io::Write;
use vaddr_lookup::VirtualAddressor;

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = cli::ParsedArgs::try_from(cli::Args::parse())?;
    let mut buffer = fs::read(&cli.binary)
        .wrap_err_with(|| format!("Could not read {}", cli.binary.display()))?;
    let intrs = run_ghidra_disassembly(
        &find_headless_ghidra(&cli.ghidra_path)?,
        &cli.binary,
        &cli.ranges,
    )?;

    let (binary, jdt) = process_binary(&mut buffer, &intrs)?;

    let binary = encrypt_compress_binary(&cli, binary)?;
    let jdt_bytes = encrypt_compress_jdt(jdt, &cli)?;

    // Write the binary and jump data table to disk
    let mut binary_file = File::create(&cli.output)
        .with_context(|| format!("Failed to create {}", cli.output.display()))?;
    binary_file.write_all(to_option_bytes(cli.encrypt, cli.compress).as_ref())?;
    binary_file.write_all(binary.as_slice())?;

    let mut jdt_file = File::create(&cli.output.with_extension("jdt"))
        .with_context(|| format!("Failed to create {}", cli.output.display()))?;
    jdt_file.write_all(to_option_bytes(cli.encrypt, cli.compress).as_ref())?;
    jdt_file.write_all(jdt_bytes.as_slice())?;

    Ok(())
}

fn encrypt_compress_binary(cli: &cli::ParsedArgs, binary: &[u8]) -> Result<Vec<u8>> {
    let binary = if cli.compress {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write(binary)
            .with_context(|| "Failed to write nanomite binary into compression buffer")?;
        enc.finish()
            .with_context(|| "Failed to compress nanomite binary")?
    } else {
        binary.to_owned()
    };
    let binary = if cli.encrypt {
        let encrypted_binary = EncryptedObject::try_from(binary.as_slice())
            .map_err(|e| eyre!(e))
            .with_context(|| "failed to encrypt binary")?;
        cereal::encode_to_vec(encrypted_binary, cereal::config::standard())?
    } else {
        binary
    };
    Ok(binary)
}

fn encrypt_compress_jdt(jdt: JumpDataTable, cli: &cli::ParsedArgs) -> Result<Vec<u8>> {
    let jdt_bytes = cereal::encode_to_vec(jdt, config::standard())
        .with_context(|| "failed to serialize jump data table")?;

    let jdt_bytes = if cli.compress {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write(&jdt_bytes)
            .with_context(|| "Failed to write nanomite binary into compression buffer")?;
        enc.finish()
            .with_context(|| "Failed to compress nanomite binary")?
    } else {
        jdt_bytes
    };

    let jdt_bytes = if cli.encrypt {
        let encrypted_obj = EncryptedObject::try_from(jdt_bytes.as_slice())
            .map_err(|e| eyre!(e))
            .with_context(|| "failed to encrypt jump data table")?;

        cereal::encode_to_vec(encrypted_obj, config::standard())
            .with_context(|| "failed to serialize jump data table")?
    } else {
        jdt_bytes
    };

    Ok(jdt_bytes)
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
    instrs: &InstrLocations,
) -> Result<(&'a [u8], JumpDataTable)> {
    info!("Ghidra reported {} instructions", instrs.len());
    let offsets = get_offsets(buffer, instrs)?;

    info!("Found {} instructions", offsets.len());
    let result = process_instructions(buffer, &offsets)?;

    Ok(result)
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

fn process_instructions<'a>(
    buffer: &'a mut [u8],
    offsets: &[(usize, usize)],
) -> Result<(&'a [u8], JumpDataTable)> {
    // Since we're modifying the buffer by placing nanomites, create a copy so we can
    // decode correctly.
    let orig_buffer = buffer.to_owned();
    let mut decoder = Decoder::new(64, &orig_buffer, DecoderOptions::NONE);

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
        let mut fake_nanomite = false;

        // TODO: add nanomites for jmp rel8/16/32
        if instr.flow_control() == FlowControl::ConditionalBranch
            && !instr.is_loopcc()
            && !instr.is_loop()
        {
            nanomite = Some(place_nanomite(buffer, *offset, &instr)?);
        } else if buffer[*offset..*offset + instr.len()].contains(&0xCC) {
            nanomite = Some(place_fake_nanomite()?);
            fake_nanomite = true;
        }

        if let Some(n) = nanomite {
            jdt.insert(*vaddr, n);

            let mut instr_bytes_str = String::with_capacity(instr.len() * 2);
            for b in &orig_buffer[*offset..*offset + instr.len()] {
                if fake_nanomite && *b == 0xCC {
                    instr_bytes_str.push_str(&format!("{:02X}", b).bold().underline().to_string());
                } else {
                    instr_bytes_str.push_str(&format!("{:02X}", b));
                }
            }
            //fake nanomite
            info!(
                "{} {:016X} {:<10}\t\t{}",
                if fake_nanomite {
                    "fake nanomite".yellow().bold().to_string()
                } else {
                    "     nanomite".green().bold().to_string()
                },
                *vaddr,
                instr_bytes_str,
                output
            );
        }
    }

    Ok((buffer, jdt))
}

fn place_fake_nanomite() -> Result<JumpData> {
    // create a real jcc instruction, and then encode it.
    let jump_type: JumpType = random();

    let mut asm = CodeAssembler::new(64)?;
    let target = max(random::<u64>() % i8::MAX as u64, 6);

    match jump_type {
        JumpType::Ja => asm.ja(target)?,
        JumpType::Jae => asm.jae(target)?,
        JumpType::Jb => asm.jb(target)?,
        JumpType::Jbe => asm.jbe(target)?,
        JumpType::Je => asm.je(target)?,
        JumpType::Jg => asm.jg(target)?,
        JumpType::Jge => asm.jge(target)?,
        JumpType::Jl => asm.jl(target)?,
        JumpType::Jle => asm.jle(target)?,
        JumpType::Jmp => asm.jmp(target)?,
        JumpType::Jne => asm.jne(target)?,
        JumpType::Jno => asm.jno(target)?,
        JumpType::Jnp => asm.jnp(target)?,
        JumpType::Jns => asm.jns(target)?,
        JumpType::Jo => asm.jo(target)?,
        JumpType::Jp => asm.jp(target)?,
        JumpType::Js => asm.js(target)?,
        _ => asm.je(target)?,
    };

    let bytes = asm.assemble(0x0)?;
    let jd = JumpData::new(jump_type, bytes.len() as u8, target as isize);

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

    // Place the nanomite
    buffer[offset] = 0xcc;

    // Replace rest of bytes with garbage
    for i in 1..instr.len() {
        buffer[offset + i] = random();
    }

    Ok(nanomite)
}
