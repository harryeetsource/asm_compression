use std::env;
use std::fs::File;
use std::io::{self, Read, Write};

mod compression;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input_file> <output_file>", args[0]);
        std::process::exit(1);
    }

    let input_path = &args[1];
    let output_path = &args[2];

    // Read input file
    let mut input_file = File::open(input_path)?;
    let mut input_data = Vec::new();
    input_file.read_to_end(&mut input_data)?;

    // Prepare output buffer
    let mut output_data = vec![0u8; input_data.len() * 2]; // Ensure the output buffer is large enough

    // Compress data
    let compressed_len = compression::compress(&input_data, &mut output_data);

    // Write compressed data to output file
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&output_data[..compressed_len])?;

    println!("Compression complete. Compressed data written to {}", output_path);
    Ok(())
}
