use crate::eyre;
use color_eyre::{eyre::ContextCompat, owo_colors::OwoColorize, Result};
use indicatif::ProgressBar;
use std::{
    env::current_dir,
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration, fs::File,
};

///  Provides virtual address of where addresses are located in the binary.
#[derive(Debug)]
pub struct InstrLocations(Vec<usize>);

pub fn run_ghidra_disassembly(ghidra_bin: &PathBuf, binary: &PathBuf) -> Result<InstrLocations> {
    let pb = ProgressBar::new_spinner();
    pb.set_message("Running Ghidra analysis".bold().to_string());
    pb.enable_steady_tick(Duration::from_millis(250));

    let tmp_dir = std::env::temp_dir();
    let script_output = tmp_dir.join("script_output.txt");

    let proj_name = binary
        .file_name()
        .wrap_err_with(|| format!("Could not get file name from {}", binary.display()))?;

    let disas_script = current_dir()?.join("res").join("get_disassembly.py");
    if !disas_script.exists() {
        return Err(eyre!("Could not find ghidra script"));
    }

    let mut cmd = Command::new(ghidra_bin)
        .arg(tmp_dir)
        .arg(proj_name)
        .arg("-import")
        .arg(binary)
        .arg("-postScript")
        .arg(disas_script)
        .arg("-scriptLog")
        .arg(script_output.as_os_str())
        .arg("-deleteProject")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let out = cmd.stdout.take().unwrap();

    // print to console
    let mut reader = BufReader::new(out);
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 {
            break;
        }

        // Don't spam console with ghidra script output
        if !line.trim().ends_with("(GhidraScript)") {
            pb.println(&line);
        }

        line.clear();
    }

    pb.finish_with_message(format!("{}", "Ghidra analysis complete.".bold()));

    let status = cmd.wait()?;
    if !status.success() {
        return Err(eyre!("Ghidra disassembly failed"));
    }

    parse_ghidra_output(&script_output)
}

fn parse_ghidra_output(script_output: &PathBuf) -> Result<InstrLocations> {
  
    let pb = ProgressBar::new_spinner();
    pb.set_message(format!("{}", "Parsing Ghidra output".bold()));
    pb.enable_steady_tick(Duration::from_millis(250));

    let mut instrs = Vec::new();
    let file = File::open(script_output)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.contains("INFO") {
            if let Some(addr) = line.split_whitespace().last() {
                let addr = usize::from_str_radix(addr, 16)?;
                instrs.push(addr);
            }   
        }
    }

    pb.finish_with_message(format!("{}", "Ghidra output parsed.".bold()));

    Ok(InstrLocations(instrs))
}
