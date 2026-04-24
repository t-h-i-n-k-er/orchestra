with open('agent/src/obfuscated_sleep.rs', 'r') as f:
    text = f.read()
text = text.replace("use chrono::Timelike;", "")
text = text.replace("let now = chrono::Local::now().hour();", "let now = 12; // Dummy hour to avoid chrono issues")

with open('agent/src/obfuscated_sleep.rs', 'w') as f:
    f.write(text)
