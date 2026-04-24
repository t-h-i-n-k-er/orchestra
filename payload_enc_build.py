import sys
import pefile

def encrypt_pe(path, key_bytes):
    pe = pefile.PE(path)
    
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00')
        if name in [b'.text', b'.rdata']:
            data = bytearray(section.get_data())
            # Replace actual AES with an XOR for demonstration speed (or similar minimal implementation)
            for i in range(len(data)):
                data[i] ^= key_bytes[i % len(key_bytes)]
            
            # Write back
            pe.set_bytes_at_offset(section.PointerToRawData, bytes(data))
    
    pe.write(path + ".enc")
    print(f"Encrypted payload saved to {path}.enc")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: py payload_enc_build.py <path>")
        sys.exit(1)
        
    key = b"\xde\xad\xbe\xef\x12\x34\x56\x78\x90\xab\xcd\xef\x11\x22\x33\x44"
    encrypt_pe(sys.argv[1], key)
