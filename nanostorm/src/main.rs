#[macro_use]
mod log;
mod ghidra_runner;
mod vaddr_lookup;

use std::{path::{Path, PathBuf}, fs::{File, self}};
use color_eyre::owo_colors::OwoColorize;
use clap::Parser;
use color_eyre::eyre::{Result, eyre};
use goblin::Object;
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
    output: Option<String>
}

#[derive(Debug)]
struct ParsedArgs {
    ghidra_path: PathBuf,
    binary: PathBuf,
    output: String
}

impl From<Args> for ParsedArgs {
    fn from(args: Args) -> Self {
        let output = match args.output {
            Some(o) => o,
            None => args.binary.file_name().unwrap().to_str().unwrap().to_string()
        };
        ParsedArgs {
            ghidra_path: args.ghidra_path,
            binary: args.binary,
            output
        }
    }
}

fn find_headless_ghidra(ghidra_path: &Path) -> Result<PathBuf> {
    let bin_name= if cfg!(target_os = "windows") {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    };

    let ghidra_headless = ghidra_path.join("support").join(bin_name);

    if !ghidra_headless.exists() {
        Err(eyre!("analyzeHeadless not found. Did you specify the correct Ghidra path?"))
    } else {
        success!("Ghidra headless path: {:?}", ghidra_headless);
        Ok(ghidra_headless)
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = ParsedArgs::from(Args::parse());

    if !Path::exists(&cli.binary) {
        return Err(eyre!("Binary does not exist"));
    }

    let ghidra_headless = find_headless_ghidra(&cli.ghidra_path)?;
    let intrs = run_ghidra_disassembly(&ghidra_headless, &cli.binary)?;
    let buffer = fs::read(cli.binary)?;

    {
        let vaddr_lookup : Box<dyn VirtualAddressor>= match Object::parse(&buffer)? {
            Object::Elf(elf)=> Ok(Box::new(ElfVirtualAddressor::new(elf)) as Box<dyn VirtualAddressor>),
            Object::PE(pe) => Ok(Box::new(PeVirtualAddressor::new(pe)) as Box<dyn VirtualAddressor>),
            _ => Err(eyre!("Unsupported binary format"))
        }?;

        vaddr_lookup.virtual_address(0x10000);
    }
    

    
    
    Ok(())
}
