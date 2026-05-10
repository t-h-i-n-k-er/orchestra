#!/usr/bin/env bash
set -euo pipefail

target_from_triple() {
  case "$1" in
    x86_64-pc-windows-msvc|x86_64-windows-msvc)
      printf '%s' "x86_64-windows-msvc"
      ;;
    aarch64-pc-windows-msvc|aarch64-windows-msvc|arm64-pc-windows-msvc|arm64-windows-msvc)
      printf '%s' "aarch64-windows-msvc"
      ;;
    *)
      printf '%s' "$1"
      ;;
  esac
}

args=()
has_target=0
zig_target="$(target_from_triple "${TARGET:-x86_64-pc-windows-msvc}")"

while (($#)); do
  arg="$1"
  shift

  case "$arg" in
    --target=x86_64-pc-windows-msvc|--target=x86_64-windows-msvc)
      args+=("-target" "x86_64-windows-msvc")
      has_target=1
      ;;
    --target=aarch64-pc-windows-msvc|--target=aarch64-windows-msvc|--target=arm64-pc-windows-msvc|--target=arm64-windows-msvc)
      args+=("-target" "aarch64-windows-msvc")
      has_target=1
      ;;
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

if [[ -d /usr/x86_64-w64-mingw32/include ]]; then
  args=(
    "-isystem" "/usr/x86_64-w64-mingw32/include"
    "-D__GNUC__=4" "-D__GNUC_MINOR__=2" "-D__GNUC_PATCHLEVEL__=0"
    "${args[@]}"
  )
fi

exec zig cc "${args[@]}"