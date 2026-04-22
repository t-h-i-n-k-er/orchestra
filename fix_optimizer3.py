import re

with open("optimizer/src/lib.rs", "r") as f:
    code = f.read()

code = code.replace('''Box::new(LeaAddPass),''', '''Box::new(LeaAddPass),
        Box::new(AddSubPass),''')

with open("optimizer/src/lib.rs", "w") as f:
    f.write(code)

