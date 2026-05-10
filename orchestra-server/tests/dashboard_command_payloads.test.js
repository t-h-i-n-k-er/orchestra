const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

class FakeElement {
  constructor(id) {
    this.id = id;
    this.value = "";
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.textContent = "";
    this.className = "";
    this.innerHTML = "";
    this.files = [];
    this.style = {};
  }

  addEventListener() {}
  click() {}
  focus() {}
  getAttribute() { return null; }
  setAttribute() {}
  querySelector() { return null; }
  querySelectorAll() { return []; }
}

function loadDashboardHooks() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, new FakeElement(id));
    return elements.get(id);
  };
  const document = {
    getElementById: element,
    querySelectorAll: () => [],
    createElement: (tag) => new FakeElement(tag),
  };

  const sandbox = {
    __ORCHESTRA_DASHBOARD_TEST__: {},
    alert: () => {},
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    Blob: class Blob {},
    clearInterval: () => {},
    console,
    crypto: { getRandomValues: (bytes) => bytes.fill(0), subtle: {} },
    document,
    fetch: async () => { throw new Error("fetch should not run in dashboard payload tests"); },
    location: { protocol: "http:", host: "localhost" },
    sessionStorage: { getItem: () => "", setItem: () => {}, removeItem: () => {} },
    setInterval: () => 0,
    setTimeout: () => 0,
    TextDecoder,
    TextEncoder,
    URL: { createObjectURL: () => "blob:test" },
    WebSocket: class WebSocket {},
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;

  const source = fs.readFileSync(path.join(__dirname, "../static/app.js"), "utf8");
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox, { filename: "app.js" });
  return sandbox.__ORCHESTRA_DASHBOARD_TEST__;
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

test("dashboard decodes hex payloads into bytes", () => {
  const hooks = loadDashboardHooks();

  assert.deepEqual(plain(hooks.hexToBytes("0x4d 5a,90-00", "Payload")), [0x4d, 0x5a, 0x90, 0x00]);
  assert.throws(() => hooks.hexToBytes("4d5", "Payload"), /even number/);
  assert.throws(() => hooks.hexToBytes("4dxx", "Payload"), /non-hex/);
});

test("dashboard ExecuteAssembly payload matches Rust Command schema", () => {
  const hooks = loadDashboardHooks();

  const command = hooks.buildCommandPayload("ExecuteAssembly", {
    assembly_data: "4d5a9000",
    args: "--mode audit",
    timeout_secs: "45",
  });

  assert.deepEqual(plain(command), {
    ExecuteAssembly: {
      data: [0x4d, 0x5a, 0x90, 0x00],
      args: ["--mode", "audit"],
      timeout_secs: 45,
    },
  });
});

test("dashboard ExecuteBOF payload matches Rust Command schema", () => {
  const hooks = loadDashboardHooks();

  const command = hooks.buildCommandPayload("ExecuteBOF", {
    bof_data: "de ad be ef",
    args: "arg1 arg2",
    timeout_secs: "60",
  });

  assert.deepEqual(plain(command), {
    ExecuteBOF: {
      data: [0xde, 0xad, 0xbe, 0xef],
      args: ["arg1", "arg2"],
      timeout_secs: 60,
    },
  });
});

test("dashboard InjectSideLoad payload uses ExportConfig schema", () => {
  const hooks = loadDashboardHooks();

  const command = hooks.buildCommandPayload("InjectSideLoad", {
    pid: "4242",
    payload_hex: "aa bb cc dd",
    forward_target: "version.dll",
    named_exports: "GetFileVersionInfoA\nVerQueryValueW",
    ordinal_exports: "1:DllRegisterServer, 2=DllUnregisterServer",
  });

  assert.deepEqual(plain(command), {
    InjectSideLoad: {
      pid: 4242,
      payload: [0xaa, 0xbb, 0xcc, 0xdd],
      export_config: {
        forward_target: "version.dll",
        named_exports: ["GetFileVersionInfoA", "VerQueryValueW"],
        ordinal_exports: [[1, "DllRegisterServer"], [2, "DllUnregisterServer"]],
      },
    },
  });
});