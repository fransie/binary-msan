#!/bin/bash

find_version="4.9.0"

mkdir build
cd build

curl -LO http://ftp.gnu.org/gnu/findutils/findutils-${find_version}.tar.xz
tar -xf findutils-${find_version}.tar.xz

export CC=/usr/bin/x86_64-alpine-linux-musl-gcc

cd findutils-${find_version}
CFLAGS="${CFLAGS} -static -O2 -ffunction-sections -fdata-sections" LDFLAGS='-Wl,--gc-sections' ./configure
make
mkdir binaries
cp xargs/xargs binaries/
cp find/find binaries/
cp locate/locate binaries/
cp locate/updatedb binaries/
cd ../..