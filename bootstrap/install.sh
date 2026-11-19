#!/usr/bin/env bash
set -e
echo "============================================================================"
echo "[Nino Bootstrap] Zero-Dependency Native Toolchain Installer"
echo "============================================================================"

CC_BIN="${CC:-gcc}"
mkdir -p bin

echo "[1/2] Compiling C11 Bootstrap Seed (bootstrap/ninoc_seed.c)..."
$CC_BIN -O3 -std=c11 bootstrap/ninoc_seed.c -o bin/ninoc_stage0 -lm -lpthread -ldl

echo "[2/2] Self-Hosting Nino Compiler (compiler/ninoc.nino -> bin/ninoc)..."
./bin/ninoc_stage0 build compiler/ninoc.nino -o bin/ninoc
rm -f bin/ninoc_stage0
cp -f bin/ninoc ninoc

echo "============================================================================"
echo "[SUCCESS] Nino native compiler installed at: bin/ninoc"
echo "============================================================================"
