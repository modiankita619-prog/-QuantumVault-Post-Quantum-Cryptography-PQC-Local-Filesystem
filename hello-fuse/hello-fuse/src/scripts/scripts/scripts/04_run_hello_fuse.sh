#!/usr/bin/env bash
# Starts the FUSE hello filesystem in the background, tests it, then unmounts.
set -e
source ~/.cargo/env 2>/dev/null || true
cd "$(dirname "$0")/../hello-fuse"
cargo build --release
mkdir -p /tmp/hello
./target/release/hello-fuse /tmp/hello &
PID=$!
sleep 2
echo "--- ls /tmp/hello"; ls /tmp/hello
echo "--- cat /tmp/hello/hello.txt"; cat /tmp/hello/hello.txt
echo "--- mount | grep hello"; mount | grep hello
fusermount3 -u /tmp/hello
wait $PID 2>/dev/null || true
echo "Unmounted. Week 1 FUSE check complete."
