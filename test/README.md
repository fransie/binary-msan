# Tests

To run the tests, execute the script `run-tests.py` with Python3 (at least version 3.9). The tests depend on the way that GCC 11.3 compiles the binaries
so that it might not work with other versions of GCC 11.3 or other compilers.

The unit tests have been disabled by default because they require an MSan-ified version of Googletest to avoid false
positives. This is quite a bit of work. If you wish to do this, follow the steps below. However, note that you have to
use clang/clang++ to build the whole binary-msan project if you include the unit test.

1. Instrumented Libc

First, build the instrumented libc and libc ABI as described here:
https://github.com/google/sanitizers/wiki/MemorySanitizerLibcxxHowTo

```bash
# clone LLVM
git clone --depth=1 https://github.com/llvm/llvm-project
cd llvm-project
mkdir build; cd build
# configure cmake
cmake -GNinja ../llvm \
	-DCMAKE_BUILD_TYPE=Release \
	-DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi" \
	-DCMAKE_C_COMPILER=clang \
	-DCMAKE_CXX_COMPILER=clang++ \
	-DLLVM_USE_SANITIZER=MemoryWithOrigins
# build the libraries
cmake --build . -- cxx cxxabi
```

If you don't have Ninja:
sudo apt-get install -y ninja-build

Problems with apt-pack? Create symlink for it. --> https://askubuntu.com/questions/1069087/modulenotfounderror-no-module-named-apt-pkg-error/1154616#1154616

2. Build googletest with it

```bash
git clone https://github.com/google/googletest.git -b release-1.12.0
cd googletest # Main directory of the cloned repository.
mkdir build # Create a directory to hold the build output.
cd build
MSAN_CFLAGS="-fsanitize=memory -stdlib=libc++ -L/home/franzi/Documents/llvm-project-llvmorg-13.0.1/llvmInstrumentedBuild/lib -lc++abi -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/llvmInstrumentedBuild/include -I/home/franzi/Documents/llvm-project-llvmorg-13.0.1/llvmInstrumentedBuild/include/c++/v1"
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS="$MSAN_CFLAGS" -DCMAKE_CXX_FLAGS="$MSAN_CFLAGS"
make -j8
```

3. Uncomment all lines needed for unit tests in the following files:
- top-level CMakeLists.txt
- src/runtimeLibrary/CMakeLists.txt