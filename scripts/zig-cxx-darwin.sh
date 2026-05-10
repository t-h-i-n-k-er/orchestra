#!/usr/bin/env bash
set -euo pipefail

args=()
has_target=0
darwin_arm64_target=0
has_mcpu=0

while (($#)); do
  arg="$1"
  shift

  case "$arg" in
    --target=x86_64-apple-macosx|--target=x86_64-apple-darwin)
      args+=("-target" "x86_64-macos")
      has_target=1
      ;;
    --target=aarch64-apple-macosx|--target=aarch64-apple-darwin|--target=arm64-apple-macosx|--target=arm64-apple-darwin)
      args+=("-target" "aarch64-macos")
      has_target=1
      darwin_arm64_target=1
      ;;
    --target=*)
      args+=("$arg")
      has_target=1
      ;;
    -target)
      if (($# > 0)); then
        t="$1"
        shift
        case "$t" in
          x86_64-apple-macosx|x86_64-apple-darwin)
            args+=("-target" "x86_64-macos")
            ;;
          aarch64-apple-macosx|aarch64-apple-darwin|arm64-apple-macosx|arm64-apple-darwin)
            args+=("-target" "aarch64-macos")
            darwin_arm64_target=1
            ;;
          *)
            args+=("-target" "$t")
            ;;
        esac
        has_target=1
      else
        args+=("-target")
      fi
      ;;
    -mcpu=*)
      args+=("$arg")
      has_mcpu=1
      ;;
    -mcpu)
      args+=("$arg")
      has_mcpu=1
      if (($# > 0)); then
        args+=("$1")
        shift
      fi
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

if ((has_target == 0)); then
  args=("-target" "x86_64-macos" "${args[@]}")
fi

if ((darwin_arm64_target == 1 && has_mcpu == 0)); then
  args+=("-mcpu=apple_m1")
fi

exec zig c++ "${args[@]}"
