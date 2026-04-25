with open("agent/src/lib.rs", "r") as f:
    text = f.read()

dummy_macro = """
#[cfg(not(feature = "direct-syscalls"))]
#[macro_export]
macro_rules! syscall {
    ($name:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr) => {
        0
    };
    ($name:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr) => {
        0
    };
}
"""

if "macro_rules! syscall" not in text:
    text = text + "\n" + dummy_macro

with open("agent/src/lib.rs", "w") as f:
    f.write(text)
