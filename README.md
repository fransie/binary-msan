# binary-msan

This tool is a binary-only implementation of Google's Memory Sanitizer ([their paper](https://doi.org/10.1109/CGO.2015.7054186)).
It finds usage of uninitialised memory for conditional branching, syscalls and pointer dereference.
Binary-msan depends on the binary rewriting toolchain zipr (their papers:
[zipr](https://doi.org/10.1109/DSN.2017.27) and [zipr++](https://doi.org/10.1145/3141235.3141240)).

## Set-up

1. Build zipr and verify it works by rewriting "ls" as described here: https://git.zephyr-software.com/opensrc/zipr.
2. Add an environment variable with the path to the zipr folder to your shell, e.g. with bash: Add
``export ZIPR_PATH=/your/path/to/zipr`` to your ```~/.bashrc``` file.
3. Clone this repo, set an env variable for the path to zipr on your machine and build:
   ```
        git clone https://github.com/fransie/binary-msan.git
        cd binary-msan
        source init.sh
        cmake .
        make
   ```
4. Add an environment variable with the path to the binmsan folder to your shell, e.g. with bash: Add
   ``export BINMSAN_HOME=/your/path/to/binmsan`` to your ```~/.bashrc``` file. 

## Usage
Use binary-msan as follows: ```./run.sh <options> <input-file> <output-file>```, for example ```./run.sh /bin/ls ls-instrumented```. 
Available options:
- `-k`: Keep going after MSan warning. The default behaviour of binary-msan is to abort the executing of the instrumented
binary after the first warning. With this option, the execution will keep going after warnings.
- `-l`: Enable debug logging to stdout. This options inserts extra instrumentation into the binary so that it prints
which binary-msan functions (incl. arguments) are called. Useful for debugging.