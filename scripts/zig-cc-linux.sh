#!/usr/bin/env bash
set -euo pipefail

target_from_triple() {
  case "$1" in
    aarch64-unknown-linux-gnu|aarch64-linux-gnu)
      printf '%s' "aarch64-linux-gnu"
      ;;
    x86_64-unknown-linux-gnu|x86_64-linux-gnu)
      printf '%s' "x86_64-linux-gnu"
      ;;
    *)
      printf '%s' "$1"
      ;;
  esac
}

args=()
has_target=0
zig_target="$(target_from_triple "${TARGET:-aarch64-unknown-linux-gnu}")"

while (($#)); do
  arg="$1"
  shift

  case "$arg" in
    --target=*)
      args+=("-target" "$(target_from_triple "${arg#--target=}")")
      has_target=1
      ;;
    -target)
      if (($# > 0)); then
        args+=("-target" "$(target_from_triple "$1")")
        shift
        has_target=1
      else
        args+=("-target")
      fi
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

if ((has_target == 0)); then
  args=("-target" "$zig_target" "${args[@]}")
fi

exec zig cc "${args[@]}"