#!/bin/bash
sed -i 's/options(nostack)/options()/g' agent/src/syscalls.rs
sed -i 's/options(pure, nomem, nostack)/options(pure, nomem)/g' agent/src/syscalls.rs
sed -i 's/options(nostack, preserves_flags)/options(preserves_flags)/g' agent/src/syscalls.rs
