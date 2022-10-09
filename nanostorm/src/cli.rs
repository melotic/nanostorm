use clap::Parser;
use color_eyre::eyre::Context;
use color_eyre::eyre::{eyre, ContextCompat, Result};
use libnanomite::VirtAddr;
use std::ops::Range;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub(crate) struct Args {
    #[clap(short, long)]
    /// The path to the root Ghidra installation.
    pub(crate) ghidra_path: PathBuf,

    #[clap()]
    /// The path to the binary to analyze.
    pub(crate) binary: PathBuf,

    #[clap(short, long)]
    /// The path to the output file.
    pub(crate) output: Option<String>,

    #[clap(short, long)]
    /// Ranges of Virtual Addresses in hex to protect with nanomites.
    pub(crate) ranges: Option<Vec<String>>,

    #[clap(short, long, default_value_t = true)]
    /// Encrypt the Jump Data Table and the binary
    pub(crate) encrypt: bool,

    #[clap(short, long, default_value_t = true)]
    // Compress the jump data table and the binary
    pub(crate) compress: bool,
}

#[derive(Debug)]
pub(crate) struct ParsedArgs {
    pub(crate) ghidra_path: PathBuf,
    pub(crate) binary: PathBuf,
    pub(crate) output: String,
    pub(crate) ranges: Option<Vec<Range<VirtAddr>>>,
    pub(crate) encrypt: bool,
    pub(crate) compress: bool,
}

impl TryFrom<Args> for ParsedArgs {
    type Error = color_eyre::eyre::Error;

    fn try_from(args: Args) -> Result<Self, Self::Error> {
        let output = match args.output {
            Some(output) => output,
            None => args
                .binary
                .file_name()
                .with_context(|| "Could not get file name")?
                .to_str()
                .with_context(|| "Could not convert file name to string")?
                .to_owned(),
        };

        // Parse the ranges, prefixed by 0x
        let ranges = match args.ranges {
            Some(ranges) => Some(
                ranges
                    .into_iter()
                    .map(|range| {
                        let range = range.replace("0x", "");
                        let range = range.split('-').collect::<Vec<_>>();

                        if range.len() != 2 {
                            return Err(eyre!("Invalid range: {}", range.join("-")));
                        }

                        let start = VirtAddr::from_str_radix(range[0], 16).with_context(|| {
                            format!("Could not parse range start: {}", range[0])
                        })?;

                        let end = VirtAddr::from_str_radix(range[1], 16)
                            .with_context(|| format!("Could not parse range end: {}", range[1]))?;

                        // ensure start > end
                        if start > end {
                            return Err(eyre!("Invalid range: {}", range.join("-")));
                        }

                        Ok(start..end)
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            None => None,
        };

        Ok(Self {
            ghidra_path: args.ghidra_path,
            binary: args.binary,
            output,
            ranges,
            encrypt: args.encrypt,
            compress: args.compress,
        })
    }
}
