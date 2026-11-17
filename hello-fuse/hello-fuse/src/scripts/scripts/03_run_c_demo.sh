#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/../c_demo"
gcc -Wall -Wextra -O2 -I. kem_demo.c qv_crypto.c -o kem_demo -loqs -lcrypto
./kem_demo
