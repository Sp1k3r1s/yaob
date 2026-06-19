use object::{FileKind, Object, ObjectSection, ObjectSymbol};
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::fs;

#[derive(Parser)]
#[command(about, version, after_help = "Yet another binary file info dumper and disassembler.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Parse symbols, imports and exports if found
    ParseSIE {
        file: String,
    },
}

struct Binary {
    data: Vec<u8>,
    kind: FileKind
}

impl Binary {
    fn load(path: &str) -> Result<Self> {
        let data = fs::read(path)?;
        let kind = FileKind::parse(&*data)?;

        match kind {
            FileKind::Pe32    |
            FileKind::Pe64    |
            FileKind::Elf32   |
            FileKind::Elf64   |
            FileKind::CoffBig |
            FileKind::Coff    |
            FileKind::MachO32 |
            FileKind::MachO64 => { }

            _ => bail!("Unsupported binary type: {:?}", kind)
        }

        Ok(Self{ data, kind })
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

            println!("Detected symbols in the binary:");
            for symbols in obj.symbols() {
                println!(" {} at 0x{}", symbols.name().unwrap_or("<unknown>"), symbols.address());
            }
        }
    }

    Ok(())
}
