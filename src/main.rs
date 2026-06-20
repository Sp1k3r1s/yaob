use object::{Architecture, FileKind, Object, ObjectSymbol};
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use capstone::{Capstone, arch::{self, BuildsCapstone}};
use std::fs;

#[derive(Parser)]
#[command(about, version, after_help = "Yet another binary file info dumper and disassembler.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Show symbols, imports and exports if found
    ParseSIE {
        file: String,
    },

    // Disassemble the file from offset start to offset end 
    Disasm {
        file: String,
        start_offset: usize,
        end_offset: usize,
    },
}

struct Binary {
    data: Vec<u8>,
    kind: FileKind,
    arch: Architecture,
}

impl Binary {
    fn load(path: &str) -> Result<Self> {
        let data = fs::read(path)?;
        let kind = FileKind::parse(&*data)?;
        let obj = object::File::parse(&*data)?;
        let arch = obj.architecture();

        Ok(Self{ data, kind, arch })
    }

    fn kind(&self) -> FileKind {
        self.kind
    }

    fn object(&self) -> Result<object::File<'_>> {
        Ok(object::File::parse(&*self.data)?)
    }

    fn bytes(&self) -> &[u8] {
        &self.data
    }

    fn arch(&self) -> Architecture {
        self.arch
    }
}

fn load_capstone(file_arch: Architecture) -> Result<Capstone> {
        let cs = match file_arch {
        Architecture::X86_64 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode64).build()?,

        Architecture::I386 => Capstone::new().x86().mode(arch::x86::ArchMode::Mode32).build()?,

        Architecture::Aarch64 => Capstone::new().arm64().build()?,

        Architecture::Arm => Capstone::new().arm().mode(arch::arm::ArchMode::Arm).build()?,

        Architecture::Mips => Capstone::new().mips().mode(arch::mips::ArchMode::Mips32).build()?,

        Architecture::Mips64 => Capstone::new().mips().mode(arch::mips::ArchMode::Mips64).build()?,


        _ => bail!("Unsupported architecture: {:?}", file_arch),
    };

    Ok(cs)
}

fn main() -> Result<()> {
    let args = Cli::parse();   

    match args.command {
        Commands::ParseSIE { file } => {
            let binary = Binary::load(&file)?;
            let obj = binary.object()?;

            match binary.kind() {
                FileKind::Pe32 |
                FileKind::Pe64 => {
                    println!("Binary imports: ");
                    for import in obj.imports()? {
                        println!(" {} from {}", String::from_utf8_lossy(import.name()), String::from_utf8_lossy(import.library()));
                    }

                    println!("Binary exports: ");
                    for export in obj.exports()? {
                        println!(" {}", String::from_utf8_lossy(export.name()));
                    }
                }

                FileKind::Elf64 |
                FileKind::Elf32 => {
                    println!("Binary symbols: ");
                    for symbol in obj.symbols() {
                        println!(" {} at {} ", symbol.name().unwrap_or("<unknown>"), symbol.address());
                    }
                }

                _ => {}
            }
        }

        Commands::Disasm { file, start_offset, end_offset } => {
            let binary = Binary::load(&file)?;
            let binary_arch = binary.arch();
            let binary_data = binary.bytes();

            if start_offset >= binary_data.len() || end_offset > binary_data.len() || start_offset >= end_offset {
                bail!("Invalid offset arguments, too big!");
            }

            let data_slice = &binary_data[start_offset..end_offset];
            let cs = load_capstone(binary_arch)?;
            let ins = cs.disasm_all(data_slice, start_offset as u64)?;

            for insn in ins.iter() {
                println!("{:#010x} {:8} {}", insn.address(), insn.mnemonic().unwrap_or("<unknown>"), insn.op_str().unwrap_or("<unknown>"));

            }

        }
    }

    Ok(())
}
