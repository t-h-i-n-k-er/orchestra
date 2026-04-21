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
      $("dash").hidden = false;
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
    // Browsers don't allow custom headers on WebSocket, so we pass the token via subprotocol.
    // The server doesn't require it for the WS endpoint here because the WS endpoint is
    // fronted by the same auth middleware via the Sec-WebSocket-Protocol fallback. For the
    // simple build we just don't open a WS if the browser blocks it; periodic REST refresh
    // keeps the dashboard live.
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

  if (token) {
    $("token").value = token;
    login();
  }
})();
