# binary-msan

This tool is a binary-only implementation of Google's Memory Sanitizer ([their paper](https://doi.org/10.1109/CGO.2015.7054186)). It finds usage of uninitialised memory for conditional branching, syscalls and pointer dereference. Binary-msan depends on the binary rewriting toolchain zipr (their papers: [zipr](https://doi.org/10.1109/DSN.2017.27) and [zipr++](https://doi.org/10.1145/3141235.3141240))

## Set-up

1. Build zipr and verify it works by rewriting "ls" as described here: https://git.zephyr-software.com/opensrc/zipr.
2. Clone this repo, set an env variable for the path to zipr on your machine and build:
   ```
        git clone https://github.com/fransie/binary-msan.git
        cd binary-msan
        export ZIPR_PATH=<YOUR/PATH/TO/ZIPR>
        source init.sh
        scons
   ```
3. Use binary-msan as follows: ```./run.sh <input-file> <output-file>```