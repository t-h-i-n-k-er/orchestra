#!/usr/bin/env bash
set -euo pipefail

out=""
files=()

while (($#)); do
  arg="$1"
  shift

  case "$arg" in
    -out:*|/out:*)
      out="${arg#*:}"
      ;;
    -nologo|/nologo)
      ;;
    *)
      files+=("$arg")
      ;;
  esac
done

if [[ -z "$out" ]]; then
  echo "zig-lib-windows-msvc.sh: missing -out:<archive>" >&2
  exit 1
fi

exec zig ar rcs "$out" "${files[@]}"