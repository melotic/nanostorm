use std::{thread, time::Duration, path::{Path, PathBuf}};

use clap::Parser;
use color_eyre::eyre::{Result, eyre};
use indicatif::ProgressBar;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, long)]
    ghidra_path: String,

    #[clap()]
    binary: String,

    #[clap(short, long)]
    output: Option<String>
}

#[derive(Debug)]
struct ParsedArgs {
    ghidra_path: String,
    binary: String,
    output: String
}

impl From<Args> for ParsedArgs {
    fn from(args: Args) -> Self {
        let output = match args.output {
            Some(o) => o,
            None => args.binary.clone()
        };
        ParsedArgs {
            ghidra_path: args.ghidra_path,
            binary: args.binary,
            output
        }
    }
}

fn find_headless_ghidra(ghidra_path: &str) -> Result<PathBuf> {
    let ghidra_path = Path::new(ghidra_path);
    let ghidra_headless = ghidra_path.join("support/analyzeHeadless");

    if !ghidra_headless.exists() {
        Err(eyre!("analyzeHeadless not found. Did you specify the correct Ghidra path?"))
    } else {
        Ok(ghidra_headless)
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = ParsedArgs::from(Args::parse());

    println!("[*] Starting nanostorm...");
    println!("[*] Ghidra path: {}", cli.ghidra_path);
    println!("[*] Binary path: {}", cli.binary);
    println!("\n[*] Locating ghidra");

    let ghidra_headless = find_headless_ghidra(&cli.ghidra_path)?;
    println!("[DEBUG] Ghidra headless path: {:?}", ghidra_headless);

    Ok(())
}
