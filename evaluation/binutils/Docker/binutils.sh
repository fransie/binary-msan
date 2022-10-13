#!/bin/bash

curl http://ftp.gnu.org/gnu/binutils/binutils-2.34.tar.xz --output binutils
tar xJf binutils
cd binutils-2.34/
sed -i -e 's/$MISSING makeinfo/true/g' configure
mkdir build
cd build
../configure --host="${TARGET}" --prefix="${STATIC_ROOT}" --disable-nls --with-stage1-ldflags="--static"
make

mkdir binaries
find binutils/ -executable -type f -exec cp {} binaries/ \;
pushd binaries
rm config.status libtool
popd
cp gprof/gprof binaries/
cp gas/as-new binaries/
cp ld/ld-new binaries/