with open("orchestra-server/static/index.html", "r") as f:
    content = f.read()

content = content.replace('<label><input type="checkbox" id="feat-keylog"> Keylogging</label>', '<label><input type="checkbox" id="feat-keylog"> Keylogging</label>\n          <label><input type="checkbox" id="feat-stealth"> Advanced Evasion Suite</label>\n          <small style="display:block;color:#888;margin-bottom:8px;">Enables the most robust detection-resistant behaviour (syscalls, OPSEC sleep, etc.)</small>')

with open("orchestra-server/static/index.html", "w") as f:
    f.write(content)

with open("orchestra-server/static/app.js", "r") as f:
    content = f.read()

content = content.replace('keylog: $("feat-keylog").checked,', 'keylog: $("feat-keylog").checked,\n        stealth: $("feat-stealth").checked,')
content = content.replace('$("feat-keylog").checked = !!data.features.keylog;', '$("feat-keylog").checked = !!data.features.keylog;\n        $("feat-stealth").checked = !!data.features.stealth;')

with open("orchestra-server/static/app.js", "w") as f:
    f.write(content)
