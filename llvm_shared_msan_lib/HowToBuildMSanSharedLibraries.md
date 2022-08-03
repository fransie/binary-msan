# How to build the LLVM MSan shared libraries

Tested on Ubuntu 20.04 Focal Fossa. I installed everything in the ~/Documents folder.


## Install GCC 11.3.0

First, you need at least version 11.2 of GCC.
```
# Get source code of GCC 11.3
cd ~/Documents
git clone git://gcc.gnu.org/git/gcc.git -b releases/gcc-11.3.0 --single-branch

##### Get GNU prerequisites
mkdir prerequisites_gcc
cd prerequisites_gcc

# Prerequisite 1: GMP
wget https://ftp.gnu.org/gnu/gmp/gmp-6.2.1.tar.xz
tar -xf gmp-6.2.1.tar.xz
cd gmp-6.2.1
./configure
make -j8
sudo make install

# Prerequisite 2: MPFR
cd ..
wget https://www.mpfr.org/mpfr-current/mpfr-4.1.0.tar.xz
tar -xf mpfr-4.1.0.tar.xz
cd mpfr-4.1.0
./configure
make -j8
sudo make install

# Prerequisite 3: MPC
cd ..
wget https://www.multiprecision.org/downloads/mpc-1.2.0.tar.gz
tar -xf mpc-1.2.0.tar.gz
cd mpc-1.2.0
./cofigure
make -j8
sudo make install

# Remove tar archives
cd ..
rm *tar*

# Make build dir
cd ..
mkdir gccbuild
cd gccbuild/

# Configure /usr to be the installation dir instead of /usr/local (default)
../gcc/configure --prefix=/usr
make bootstrap-lean -j8
sudo make instcd

# Make sure gcc 11.3 is used from now on:
gcc -v
# should give you 11.3, otherwise use the tool update-alternatives to point to correct gcc binary

# Copy lib and change softlink to point to new libstdc++.so.6.0.29
sudo cp /usr/lib64/libstdc++.so.6.0.29 /lib/x86_64-linux-gnu/
sudo ln -sf /lib/x86_64-linux-gnu/libstdc++.so.6.0.29 /lib/x86_64-linux-gnu/libstdc++.so.6
```

## LLVM 13.0.1

This installation will take A LOT of disk space, something like 70 GB. You need to use GCC version >= 11.2 for this.

```
# Get source code of LLVM 13.0.1
cd ~/Documents
wget https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-13.0.1.zip
unzip llvmorg-13.0.1.zip
rm llvmorg-13.0.1.zip

# Make build dir
mkdir llvmbcduild
cd llvmbuild

# Build (This will take FOREVER. Go grab a coffee and take a walk.)
cmake ../llvm-project-llvmorg-13.0.1/llvm
cmake --build .
sudo cmake --build . --target install

```

## Compiler-RT

Compiler-RT is the project that contains all the LLVM sanitizers. You have to use an adapted version of the folder 
`compiler-rt/lib` so that the build produces shared MSan libraries instead of static ones. Delete this folder and replace
it by the `compiler-rt-lib` folder that you find in the folder `llvm_shared_msan_lib` of this repo.

```
################################
# Replace compiler-rt folder! ##
################################

cd ~/Documents/llvm-project-llvmorg-13.0.1
mkdir compilerRT-build
cd compilerRT-build

CC=gcc CXX=g++ cmake ../compiler-rt/ -DLLVM_CONFIG_PATH=../../llvmbuild/bin/llvm-config
make -j8

# In case you get an error from a missing python module, try:
sudo apt install python3-distutildscd
```

You should now find the resulting libraries in '~/Documents/llvm-project-llvmorg-13.0.1/compilerRT-build/lib/linux'.
