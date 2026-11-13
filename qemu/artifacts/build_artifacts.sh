#!/bin/bash
# Build the two pre-placed exploit artifacts on the QEMU VM.
#
#   shocker      : static ELF, CAP_DAC_READ_SEARCH + open_by_handle_at PoC
#   escape.ko    : kernel module, CAP_SYS_MODULE + call_usermodehelper PoC
#
# Artifacts land in $ARTIFACTS so they can be scp'd back to the repo.
#
# Usage:  bash build_artifacts.sh
set -euo pipefail

SRC_DIR="${SRC_DIR:-/tmp/dsh-src}"
ARTIFACTS="${ARTIFACTS:-/tmp/dsh-artifacts}"

mkdir -p "$ARTIFACTS"

echo "=== toolchain ==="
gcc --version | head -1
echo "kernel: $(uname -r)"

# ---------------------------------------------------------------------------
# 1. shocker -- static build so it runs inside alpine (musl) as well
# ---------------------------------------------------------------------------
echo
echo "=== building shocker (static) ==="
gcc -O2 -static -Wall -o "$ARTIFACTS/shocker" "$SRC_DIR/shocker.c"
file "$ARTIFACTS/shocker" 2>/dev/null || true
ls -l "$ARTIFACTS/shocker"

# ---------------------------------------------------------------------------
# 2. escape.ko -- must match the RUNNING kernel's vermagic
# ---------------------------------------------------------------------------
echo
echo "=== building escape.ko for $(uname -r) ==="
rm -rf "$ARTIFACTS/modbuild"
mkdir -p "$ARTIFACTS/modbuild"
cp "$SRC_DIR/escape.c" "$SRC_DIR/Makefile" "$ARTIFACTS/modbuild/"
make -C "$ARTIFACTS/modbuild" 2>&1 | tail -6

cp "$ARTIFACTS/modbuild/escape.ko" "$ARTIFACTS/escape.ko"
ls -l "$ARTIFACTS/escape.ko"

echo
echo "=== vermagic check ==="
modinfo "$ARTIFACTS/escape.ko" 2>/dev/null | grep -E '^(vermagic|name|description)' || true

echo
echo "=== done ==="
ls -l "$ARTIFACTS/shocker" "$ARTIFACTS/escape.ko"
