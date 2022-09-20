#[macro_use]
mod log;
mod ghidra_runner;

use std::path::{Path, PathBuf};
use color_eyre::owo_colors::OwoColorize;
use clap::Parser;
use color_eyre::eyre::{Result, eyre};

use crate::ghidra_runner::run_ghidra_disassembly;

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
    success!("Ghidra headless path: {:?}", ghidra_headless);

    run_ghidra_disassembly(&ghidra_headless, &cli.binary)?;
    Ok(())
}
