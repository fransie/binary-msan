# binary-msan

This tool is a binary-only implementation of Google's Memory Sanitizer ([their paper](https://doi.org/10.1109/CGO.2015.7054186)).
It finds usage of uninitialised memory for conditional branching, syscalls and pointer dereference.
Binary-msan depends on the binary rewriting toolchain zipr (their papers:
[zipr](https://doi.org/10.1109/DSN.2017.27) and [zipr++](https://doi.org/10.1145/3141235.3141240)).

## Set-up

This set-up has been tested on Ubuntu 20.04 Focal Fossa.

// TODO: document installation of libclang msan shared libraries & creation of folders: clang_msan_libs and plugins_install
1. Build zipr and verify it works by rewriting "ls" as described here: https://git.zephyr-software.com/opensrc/zipr.
2. Add an environment variable with the path to the zipr folder to your shell, e.g. with bash: Add
``export ZIPR_PATH=/your/path/to/zipr`` to your ```~/.bashrc``` file.
3. Clone this repo and build:
   ```
        git clone https://github.com/fransie/binary-msan.git
        cd binary-msan
        source init.sh
        cmake .
        make
   ```
4. Add an environment variable with the path to the binmsan folder to your shell, e.g. with bash: Add
   ``export BINMSAN_HOME=/your/path/to/binmsan`` to your ```~/.bashrc``` file. 

### Shared MSan library

Binary-msan needs shared libraries of the LVVM Memory Sanitizer, which are not available in the regular build of LLVM.
Therefore, the folder `llvm_shared_msan_lib` contains the two needed libraries for x86-64. In case you need the libraries
for other architectures or they do not work on your machine, you can rebuild them yourself. You can find detailed
descriptions of how to build the libraries in the folder `llvm_shared_msan_lib`.

## Usage
Use binary-msan as follows: ```./run.sh <options> <input-file> <output-file>```, for example ```./run.sh /bin/ls ls-instrumented```. 
Available options:
- `-k`: Keep going after MSan warning. The default behaviour of binary-msan is to abort the executing of the instrumented
binary after the first warning. With this option, the execution will keep going after warnings.
- `-l`: Enable debug logging to stdout. This options inserts extra instrumentation into the binary so that it prints
which binary-msan functions (incl. arguments) are called. Useful for debugging.