import os

path = '/home/replicant/la/builder/src/bin/orchestra-pe-hardener.rs'
os.makedirs(os.path.dirname(path), exist_ok=True)

with open(path, 'w') as f:
    f.write("""use goblin::pe::{PE, options::ParseOptions};
use std::fs;
use std::path::PathBuf;
use std::env;
use rand::{Rng, thread_rng};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <input_pe> <output_pe>", args[0]);
        return Ok(());
    }

    let input_path = &args[1];
    let output_path = &args[2];
    
    let mut buffer = fs::read(input_path)?;
    let buffer_len = buffer.len();

    let pe = PE::parse(&buffer)?;
    
    let mut rng = thread_rng();

    // 1. TimeDateStamp zeroing
    let file_header_offset = pe.header.dos_header.pe_pointer as usize + 4; // after 'PE\\0\\0'
    if file_header_offset + 20 <= buffer_len {
        for i in 0..4 {
            buffer[file_header_offset + 4 + i] = 0; // TimeDateStamp is at offset 4 from file header
        }
    }

    // 2. Rich Header Removal
    // Look for 'DanS' (Rich header signature) backwards from PE header
    let pe_start = pe.header.dos_header.pe_pointer as usize;
    let mut rich_start = 0;
    for i in (0..pe_start).rev() {
        if i + 4 <= buffer_len && &buffer[i..i+4] == b"DanS" {
            // Find XOR key
            let xor_key = &buffer[i+4..i+8];
            // Find 'Rich' string (before DanS mapped XOR'd)
            for j in (0..i).rev() {
                if j + 4 <= buffer_len && &buffer[j..j+4] == b"Rich" {
                    rich_start = j;
                    break;
                }
            }
            if rich_start > 0 {
                // Zero out from rich_start down to just after DOS stub
                let dos_stub_end = 0x40; // Approx
                for k in dos_stub_end..pe_start {
                    buffer[k] = 0;
                }
            }
            break;
        }
    }

    // 3. Section name randomization & 4. Entropy padding
    let sections_offset = file_header_offset + 20 + pe.header.coff_header.size_of_optional_header as usize;
    let num_sections = pe.header.coff_header.number_of_sections as usize;
    
    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for i in 0..num_sections {
        let section_offset = sections_offset + (i * 40); // 40 bytes per section header
        if section_offset + 8 <= buffer_len {
            // Randomize name
            for j in 0..8 {
                buffer[section_offset + j] = chars[rng.gen_range(0..chars.len())];
            }
        }
    }

    // Entropy padding
    let mut padding = vec![0u8; rng.gen_range(1024..4096)];
    rng.fill(padding.as_mut_slice());
    buffer.extend(padding);

    fs::write(output_path, &buffer)?;
    println!("PE Hardened successfully.");
    Ok(())
}
""")

