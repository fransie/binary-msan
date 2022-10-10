#!/bin/bash
# build static coreutils because we need exercises in minimalism
# MIT licensed: google it or see robxu9.mit-license.org.
#
# For Linux, also builds musl for truly static linking.

coreutils_version="9.1"

if [ -d build ]; then
  echo "========= removing previous build directory"
  rm -rf build
fi

mkdir build # make build directory
pushd build

# download tarballs
echo "========= downloading coreutils"
curl -LO http://ftp.gnu.org/gnu/coreutils/coreutils-${coreutils_version}.tar.xz

echo "========= extracting coreutils"
tar xJf coreutils-${coreutils_version}.tar.xz

echo "========= building coreutils"
pushd coreutils-${coreutils_version}
export CFLAGS="${CFLAGS} -static -Os -ffunction-sections -fdata-sections"
export LDFLAGS='-Wl,--gc-sections'
export FORCE_UNSAFE_CONFIGURE=1
./configure
make


popd # coreutils-${coreutils_version}
mkdir static-coreutils
find coreutils-${coreutils_version}/src/ -type f -perm /a+x -exec cp {} static-coreutils \;

popd # build
echo "========= done"