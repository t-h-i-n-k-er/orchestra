import re

with open('/home/replicant/la/hollowing/src/windows_impl.rs', 'r') as f:
    text = f.read()

# Replace TLS trampoline
tls_tramp = r"""
                if !tls_callbacks.is_empty() {
                    let mut stub: Vec<u8> = Vec::new();
                    let ib = image_base as usize as u64;
                    #[cfg(target_arch = "x86_64")]
                    {
                        for &cb in &tls_callbacks {
                            stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp,0x28
                            stub.push(0x48);
                            stub.push(0xB9); // mov rcx, imm64
                            stub.extend_from_slice(&ib.to_le_bytes());
                            stub.extend_from_slice(&[0xBA, 0x01, 0x00, 0x00, 0x00]); // mov edx,1
                            stub.extend_from_slice(&[0x45, 0x31, 0xC0]); // xor r8d,r8d
                            stub.push(0x48);
                            stub.push(0xB8); // mov rax, imm64
                            stub.extend_from_slice(&(cb as u64).to_le_bytes());
                            stub.extend_from_slice(&[0xFF, 0xD0]); // call rax
                            stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]); // add rsp,0x28
                        }
                        stub.push(0x48);
                        stub.push(0xB8); // mov rax, imm64 (entry_point)
                        stub.extend_from_slice(&(entry_point as u64).to_le_bytes());
                        stub.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
                    }
                    #[cfg(target_arch = "x86")]
                    {
                        for &cb in &tls_callbacks {
                            // stdcall / cdecl setup for x86
                            stub.extend_from_slice(&[0x6A, 0x00]); // push 0 (lpvReserved)
                            stub.extend_from_slice(&[0x6A, 0x01]); // push 1 (DLL_PROCESS_ATTACH)
                            stub.push(0x68); // push imm32 (imagebase)
                            stub.extend_from_slice(&(ib as u32).to_le_bytes());
                            stub.push(0xB8); // mov eax, imm32 (cb)
                            stub.extend_from_slice(&(cb as u32).to_le_bytes());
                            stub.extend_from_slice(&[0xFF, 0xD0]); // call eax
                        }
                        stub.push(0xB8); // mov eax, imm32 (entry)
                        stub.extend_from_slice(&(entry_point as u32).to_le_bytes());
                        stub.extend_from_slice(&[0xFF, 0xE0]); // jmp eax
                    }
"""

if 'let mut stub: Vec<u8> = Vec::new();' in text:
    text = re.sub(r'let mut stub: Vec<u8> = Vec::new\(\);.*?stub\.extend_from_slice\(&\[0xFF, 0xE0\]\); // jmp rax', tls_tramp.strip(), text, flags=re.DOTALL | re.MULTILINE)

with open('/home/replicant/la/hollowing/src/windows_impl.rs', 'w') as f:
    f.write(text)

