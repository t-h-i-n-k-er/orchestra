with open("agent/src/persistence.rs", "r") as f:
    text = f.read()

text = text.replace("pub mod windows {", "pub use windows::*;\n#[cfg(windows)]\npub mod windows {")
text = text.replace("pub mod macos {", "pub use macos::*;\n#[cfg(target_os = \"macos\")]\npub mod macos {")

with open("agent/src/persistence.rs", "w") as f:
    f.write(text)
