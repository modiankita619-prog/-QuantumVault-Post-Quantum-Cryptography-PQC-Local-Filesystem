#!/usr/bin/env bash
set -e
cd ~
[ -d liboqs ] || git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir -p build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release ..
ninja
sudo ninja install
sudo ldconfig
ls /usr/local/include/oqs/oqs.h && echo "liboqs installed OK"
