use goblin::pe::{PE, options::ParseOptions};
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

    // Extract all the offsets we need from the PE *before* taking any mutable
    // references to buffer, so we avoid conflicting borrows (E0502).
    let (file_header_offset, pe_start, sections_offset, num_sections) = {
        let pe = PE::parse(&buffer)?;
        let fh_off = pe.header.dos_header.pe_pointer as usize + 4;
        let pe_s = pe.header.dos_header.pe_pointer as usize;
        let sec_off = fh_off + 20 + pe.header.coff_header.size_of_optional_header as usize;
        let nsec = pe.header.coff_header.number_of_sections as usize;
        (fh_off, pe_s, sec_off, nsec)
        // `pe` is dropped here, releasing the immutable borrow of `buffer`
    };

    let mut rng = thread_rng();

    // 1. TimeDateStamp zeroing
    if file_header_offset + 20 <= buffer_len {
        for i in 0..4 {
            buffer[file_header_offset + 4 + i] = 0;
        }
    }

    // 2. Rich Header Removal — scan backwards from PE header for 'DanS'
    let mut rich_start = 0usize;
    for i in (0..pe_start).rev() {
        if i + 4 <= buffer_len && &buffer[i..i + 4] == b"DanS" {
            for j in (0..i).rev() {
                if j + 4 <= buffer_len && &buffer[j..j + 4] == b"Rich" {
                    rich_start = j;
                    break;
                }
            }
            if rich_start > 0 {
                let dos_stub_end = 0x40;
                for k in dos_stub_end..pe_start {
                    buffer[k] = 0;
                }
            }
            break;
        }
    }

    // 3. Section name randomization
    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for i in 0..num_sections {
        let section_offset = sections_offset + (i * 40);
        if section_offset + 8 <= buffer_len {
            for j in 0..8 {
                buffer[section_offset + j] = chars[rng.gen_range(0..chars.len())];
            }
        }
    }

    // 4. Entropy padding
    let mut padding = vec![0u8; rng.gen_range(1024..4096)];
    rng.fill(padding.as_mut_slice());
    buffer.extend(padding);

    fs::write(output_path, &buffer)?;
    println!("PE Hardened successfully.");
    Ok(())
}
