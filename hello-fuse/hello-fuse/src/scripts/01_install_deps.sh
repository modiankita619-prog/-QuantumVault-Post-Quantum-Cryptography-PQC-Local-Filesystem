#!/usr/bin/env bash
set -e
sudo apt update
sudo apt install -y build-essential cmake ninja-build git pkg-config \
     libssl-dev fuse3 libfuse3-dev xxd curl
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
echo "Done. Run: source ~/.cargo/env"
