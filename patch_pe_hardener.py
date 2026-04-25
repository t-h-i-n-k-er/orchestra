import re

with open("builder/src/bin/orchestra-pe-hardener.rs", "r") as f:
    text = f.read()

# Replace parsing
text = text.replace('let pe = PE::parse(&buffer)?;\n    \n    let mut rng = thread_rng();', '''let mut rng = thread_rng();
    
    let (file_header_offset, pe_start, size_of_optional_header, number_of_sections) = {
        let pe = PE::parse(&buffer)?;
        (
            pe.header.dos_header.pe_pointer as usize + 4,
            pe.header.dos_header.pe_pointer as usize,
            pe.header.coff_header.size_of_optional_header as usize,
            pe.header.coff_header.number_of_sections as usize,
        )
    };''')

# Replace usage of `pe.header.dos_header.pe_pointer as usize + 4`
text = re.sub(r'let file_header_offset = [^;]+;', '', text) 
text = re.sub(r'let pe_start = [^;]+;', '', text)

# Replace usage
text = text.replace('pe.header.coff_header.size_of_optional_header as usize', 'size_of_optional_header')
text = text.replace('pe.header.coff_header.number_of_sections as usize', 'number_of_sections')
text = text.replace('let xor_key = &buffer[i+4..i+8];', 'let _xor_key = &buffer[i+4..i+8];')

with open("builder/src/bin/orchestra-pe-hardener.rs", "w") as f:
    f.write(text)

