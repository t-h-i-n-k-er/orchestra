import os
import re

with open('optimizer/src/lib.rs', 'r') as f:
    content = f.read()

# Fix the fallback heuristic to not break on first ret, wait for int3 (0xCC) or nops (0x90).
# This is a basic heuristic for finding function ends in x86_64.
fallback_logic_old = """        while tmp_size < 10000 {
            let slice = unsafe { std::slice::from_raw_parts(curr_ptr as *const u8, 15) };
            let decoder = Decoder::with_ip(64, slice, curr_ptr, DecoderOptions::NONE);
            if let Some(ins) = decoder.into_iter().next() {
                tmp_size += ins.len();
                curr_ptr += ins.len() as u64;
                if ins.code() == iced_x86::Code::Retnq || ins.code() == iced_x86::Code::Retnw {
                    size = tmp_size;
                    break;
                }
            } else {
                break;
            }
        }"""
        
fallback_logic_new = """        let mut consecutive_padding = 0;
        while tmp_size < 10000 {
            let slice = unsafe { std::slice::from_raw_parts(curr_ptr as *const u8, 15) };
            let decoder = iced_x86::Decoder::with_ip(64, slice, curr_ptr, iced_x86::DecoderOptions::NONE);
            if let Some(ins) = decoder.into_iter().next() {
                tmp_size += ins.len();
                curr_ptr += ins.len() as u64;
                if ins.code() == iced_x86::Code::Int3 || ins.code() == iced_x86::Code::Nopd || ins.code() == iced_x86::Code::Nopq || ins.code() == iced_x86::Code::Nopw {
                    consecutive_padding += ins.len();
                    if consecutive_padding >= 2 {
                        size = tmp_size - consecutive_padding;
                        break;
                    }
                } else {
                    consecutive_padding = 0;
                }
            } else {
                break;
            }
        }"""

content = content.replace(fallback_logic_old, fallback_logic_new)

# In Windows they have the same logic:
fallback_logic_win_old = """    while tmp_size < 10000 {
        let slice = unsafe { std::slice::from_raw_parts(curr_ptr as *const u8, 15) };
        let decoder = Decoder::with_ip(64, slice, curr_ptr, DecoderOptions::NONE);
        if let Some(ins) = decoder.into_iter().next() {
            tmp_size += ins.len();
            curr_ptr += ins.len() as u64;
            if ins.code() == iced_x86::Code::Retnq || ins.code() == iced_x86::Code::Retnw {
                size = tmp_size;
                break; // Very naive
            }
        } else {
            break;
        }
    }"""
    
content = content.replace(fallback_logic_win_old, fallback_logic_new)

with open('optimizer/src/lib.rs', 'w') as f:
    f.write(content)

