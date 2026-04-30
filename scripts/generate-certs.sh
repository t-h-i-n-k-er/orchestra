#!/usr/bin/env bash
# scripts/generate-certs.sh — Generate a self-signed TLS certificate for the
# Orchestra Control Center.
#
# Usage:
#   ./scripts/generate-certs.sh [--out DIR] [--san EXTRA_SAN ...]
#
# Defaults: secrets/server.crt + secrets/server.key (relative to repo root).
# Prints the SHA-256 fingerprint to stdout for profile pinning.
#
# Required: openssl

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT_DIR="secrets"
DAYS=365
CURVE="P-256"
CN="orchestra-control-center"
SAN_IPS=("127.0.0.1")
SAN_DNS=("localhost")

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out)   OUT_DIR="$2"; shift 2 ;;
        --days)  DAYS="$2";   shift 2 ;;
        --cn)    CN="$2";     shift 2 ;;
        --san)
            # Accept IP: or DNS: prefixed SANs
            if [[ "$2" == IP:* ]]; then SAN_IPS+=("${2#IP:}"); elif [[ "$2" == DNS:* ]]; then SAN_DNS+=("${2#DNS:}"); else SAN_IPS+=("$2"); fi
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--out DIR] [--days N] [--cn NAME] [--san IP:x.x.x.x] [--san DNS:example.com]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$OUT_DIR"

CERT="$OUT_DIR/server.crt"
KEY="$OUT_DIR/server.key"

# Detect LAN IP
DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -n "$DETECTED_IP" && " ${SAN_IPS[*]} " != *" $DETECTED_IP "* ]] && SAN_IPS+=("$DETECTED_IP")

# Build subjectAltName string
SAN_STR=""
for ip in "${SAN_IPS[@]}"; do
    [[ -n "$SAN_STR" ]] && SAN_STR+=","
    SAN_STR+="IP:${ip}"
done
for dns in "${SAN_DNS[@]}"; do
    [[ -n "$SAN_STR" ]] && SAN_STR+=","
    SAN_STR+="DNS:${dns}"
done

echo "Generating self-signed TLS certificate..."
echo "  CN:   $CN"
echo "  SAN:  $SAN_STR"
echo "  Days: $DAYS"
echo "  Key:  EC $CURVE"
echo "  Out:  $CERT / $KEY"
echo

openssl req -x509 -nodes -newkey ec -pkeyopt "ec_paramgen_curve:${CURVE}" \
    -days "$DAYS" \
    -keyout "$KEY" -out "$CERT" \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=${SAN_STR}"

chmod 600 "$KEY"

# Print fingerprint
FP=$(openssl x509 -in "$CERT" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
echo
echo "Certificate SHA-256 fingerprint: $FP"
echo
echo "Add to a profile for cert pinning:"
echo "  server_cert_fingerprint = \"$FP\""
