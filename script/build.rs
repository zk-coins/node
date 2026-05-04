use std::path::Path;

fn main() {
    let elf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../elf/zkcoins-program")
        .canonicalize()
        .expect("Pre-built ELF not found at elf/zkcoins-program. Build with: cargo prove build --release -p zkcoins-program");

    println!("cargo:rustc-env=SP1_ELF_zkcoins-program={}", elf.display());
    println!("cargo:rerun-if-changed={}", elf.display());
}
