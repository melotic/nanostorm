
# :cloud: nanostorm

Nanostorm is an EDR evasion tool written in Rust for Windows and Linux binaries that places *nanomites* in the target executable, and packs and encrypts it.


## Badges

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/melotic/nanostorm/check)](https://github.com/melotic/nanostorm/actions/workflows/check.yml)
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/)


## Authors

- [@melotic](https://www.github.com/melotic) -- https://melotic.xyz


## Contributing

Contributions are always welcome!



## Features

- Toggable ability to encrypt(`-e`) and compress (`-c`) the binary, and jump data table
- In memory execution of stub
- Ability to write your own stub, using `libnanomite`
- No current (_as of Oct 2022_) AV detections

## Usage/Examples

First, compile _nanostorm_ to create nanomite infected binaries. _nanostorm_ requires the installation of [Ghidra](https://ghidra-sre.org).

You will need to pass the path of _Ghidra) to _nanostorm_ with `-g /path/to/ghidra-root`

```bash
cargo build --release --bin nanostorm
```

Next, you'll have to create a binary with nanomites:

```bash
./target/release/nanostorm -g /path/to/ghidra a.out
```

**Or**, to encrypt and compress the binary and Jump Data Table (**recommended**, albeit increase in startup time):

```bash
./target/release/nanostorm -g /path/to/ghidra -e -c a.out
```

Next, compile the provided stub with the nanomite binary and its Jump Data table:

```bash
NANOSTORM_BIN=a.nanomites NANOSTORM_JDT=a.jdt cargo build --bin stub --release
```

## Roadmap

- Windows support (soon :tm:)
