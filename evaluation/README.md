# Evaluation

## Instruction Counting

This evaluation step counts the number of distinct Intel syntax mnemonics in the static versions of the binutils,
coreutils, and findutils package binaries. The binaries have to be placed in the respective `<package>/binaries` folder.

1. Unzip the `gold` binary in folder `binary-msan/evaluation/binutils/binaries`. (The binary is too large for GitHub.)
2. Run the preparations script, which counts the mnemonics with a Zipr plugin called "counter":
   `python3  binary_preparations.py`
3. Run the evaluation script: `python3 instruction_counting.py`.

You can find the results in the `results` folder afterwards. Apart from some PDf graphics, it
should contain the relevant data in:
- `instructions_per_binary.csv` --> How many distinct mnemonics does each binary use?
- `instructions_sorted_by_appearance.csv` --> How many binaries does each mnemonic appear in (sorted from highest to lowest occurence)?
- `covered_binaries_with_given_instructions.csv` --> If the first x instructions in the order of `instructions_sorted_by_appearance.csv` were instrumented,
  which binaries could be completely instrumented?

## Instrumentation and Run-time Performance

The evaluation step measures the instrumentation time and file size increase as well as the run-time of
the considered UUM detection tools MemorySanitizer, BinMSan, Dr. Memory and Memcheck.

1. Set env variables: `source ../init.sh`
2. Make sure that Valgrind (Memcheck) and Dr. Memory are installed and on the PATH.
3. For the graphics, you need the cochineal font. Replace it in the code of `performance_measurement.py` if you don't have it.
4. Replace the path to your instrumented libcxx build on top of the `performance_measurement.py` file. See below if
you don't have that yet.
5. Run `python3 performance_measurement.py`

The results will show up in the `results` folder:
- `compile_sanitize_times.csv`
- `file_size.csv`
- `run_time_performance.csv`

### How to build an instrumented libcxx

Description from here:
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
`sudo apt-get install -y ninja-build`

Problems with apt-pack? Create symlink for it. --> https://askubuntu.com/questions/1069087/modulenotfounderror-no-module-named-apt-pkg-error/1154616#1154616
