use color_eyre::{
    eyre::ContextCompat,
    Result, owo_colors::OwoColorize,
};
use indicatif::ProgressBar;
use std::{
    env::current_dir,
    path::PathBuf,
    process::{Command, Stdio}, io::{BufRead, BufReader}, time::Duration,
};
use crate::eyre;

///  Provides virtual address of where addresses are located in the binary.
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
        .spawn()?;

    let out = cmd.stdout.take().unwrap();

    // print to console
    let mut reader = BufReader::new(out);
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap() > 0 {
        pb.println(&line);
    }

    let status = cmd.wait()?;
    if !status.success() {
        return Err(eyre!("Ghidra disassembly failed"));
    }

    //temportar
    Ok(InstrLocations(vec![]))
}
