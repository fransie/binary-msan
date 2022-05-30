# binary-msan

This tool is a binary-only implementation of Google's Memory Sanitizer ([their paper](https://doi.org/10.1109/CGO.2015.7054186)). It finds usage of uninitialised memory for conditional branching, syscalls and pointer dereference. Binary-msan depends on the binary rewriting toolchain zipr (their papers: [zipr](https://doi.org/10.1109/DSN.2017.27) and [zipr++](https://doi.org/10.1145/3141235.3141240))

## Set-up

1. Build zipr and verify it works by rewriting "ls" as described here: https://git.zephyr-software.com/opensrc/zipr.
2. Add an environment variable with the path to the zipr folder to your shell, e.g. with bash: Add
``export ZIPR_PATH=/your/path/to/zipr`` to your ```~/.bashrc``` file right before the following line: 
    ```
   # If not running interactively, don't do anything
    ```
3. Clone this repo, set an env variable for the path to zipr on your machine and build:
   ```
        git clone https://github.com/fransie/binary-msan.git
        cd binary-msan
        source init.sh
        cmake .
        make
   ```
4. Use binary-msan as follows: ```./run.sh <input-file> <output-file>```, for example ```./run.sh /bin/ls ls-instrumented```
```source init.sh``` sets all the necessary environment variables. So whenever you start a new shell, remember to execute
the script if you're missing env variables.

TODO: Come up with strategy to distribute shared msan libraries and keep in mind that they have to be compiled with GCC >11.2
but the rest of the project is known to work only when compiled with GCC 9.