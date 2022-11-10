#!/bin/bash

ln -s /usr/bin/x86_64-alpine-linux-musl-gcc-ar /usr/bin/x86_64-alpine-linux-musl-ar

export TARGET=x86_64-alpine-linux-musl
export STATIC_ROOT=$(readlink -f ~/${TARGET}-static)
binutils_version=2.38

curl http://ftp.gnu.org/gnu/binutils/binutils-${binutils_version}.tar.xz --output binutils
tar xJf binutils
cd binutils-${binutils_version}/
sed -i -e 's/$MISSING makeinfo/true/g' configure
mkdir build
cd build
../configure --host="${TARGET}" --prefix="${STATIC_ROOT}" --disable-nls --with-stage1-ldflags="--static" --enable-gold --enable-gprofng=yes
make

mkdir binaries
find binutils/ -executable -type f -exec cp {} binaries/ \;
pushd binaries
rm config.status libtool bfdtest* gentestdlls sysinfo
popd
cp gprof/gprof binaries/
cp gas/as-new binaries/
cp ld/ld-new binaries/
cp gold/ld-new binaries/gold