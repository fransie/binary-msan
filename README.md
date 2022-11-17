# BinMSan

This tool is a PoC of a binary-only implementation of LLVM's Memory Sanitizer (see [their paper](https://doi.org/10.1109/CGO.2015.7054186)).
It finds usage of uninitialised memory in conditional branching, indirect branching, syscalls, libc function calls, and pointer dereference.
Binary-msan depends on the binary rewriting toolchain zipr (see their papers
[zipr](https://doi.org/10.1109/DSN.2017.27) and [zipr++](https://doi.org/10.1145/3141235.3141240)).

## Set-up

This set-up has been tested on Ubuntu 20.04 Focal Fossa.

1. Build zipr and verify it works by rewriting "ls" as described here: https://git.zephyr-software.com/opensrc/zipr.
2. Add an environment variable with the path to the zipr folder to your shell, e.g. with bash: Add
``export ZIPR_PATH=/your/path/to/zipr`` to your ```~/.bashrc``` file.
4. Clone this repo:
   ```
   git clone https://github.com/fransie/binary-msan.git
   ```
   and add an environment variable `BINMSAN_HOME` with the path to the binary-msan folder to your shell, e.g. with bash: Add
   ``export BINMSAN_HOME=/your/path/to/binary-msan`` to your ```~/.bashrc``` file.
5. Build binary-msan:
   ```
        cd binary-msan
        source init.sh
        cmake .
        make
   ```

### Shared MSan library

BinMSan needs shared libraries of the LVVM MemorySanitizer, which are not available in the regular build of LLVM.
Therefore, the folder `llvm_shared_msan_lib` contains the two needed libraries for x86-64. Hence, you don't need to build
them yourself but if you're interested, you can find the descriptions of how to build the libraries in the folder `llvm_shared_msan_lib`.

## Usage

Use BinMSan as follows: ```./binary-msan.sh <options> <input-file> <output-file>```. This is only a prototype,
so it will only instrument the main function. Have a look into the test folder for example binaries.
Available options:
- `-k`: Keep going after MSan warning. The default behaviour of BinMSan is to abort the executing of the instrumented
binary after the first warning. With this option, the execution will keep going after warnings.
- `-l`: Enable debug logging to stdout. This options inserts extra instrumentation into the binary so that it prints
which BinMSan runtime functions (incl. arguments) are called. Useful for debugging.