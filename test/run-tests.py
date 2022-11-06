import os
import re
import subprocess
import sys
from os import listdir
from os.path import isfile, join
import concurrent.futures

CLEAN_SCRIPT = "./clean.sh"
GREEN = '\033[92m'
RED = '\033[91m'
END = '\033[0m'


def verify_expected_output(filename):
    directory = filename.split("/")[0]
    lines = open(filename, "r").readlines()
    last_line = lines[-1:].pop()

    log = filename.split("/")[1].removesuffix(".cpp") + ".txt"
    log_lines = open(f"{directory}/logs/{log}", "r").readlines()

    expectation = last_line.replace("// EXPECTED: ", "").strip("\n")
    line_num = 1
    for line in log_lines:
        if expectation in line:
            print(
                f"******* {filename} *******\n{GREEN}SUCCESS: Found expected output in {directory}/logs/{log}. Expected: '{expectation}'{END}")
            break
        if line_num == len(log_lines):
            print(
                f"******* {filename} *******\n{RED}ERROR: Expected output was not in {directory}/logs/{log}. Expected: '{expectation}'{END}")
            break
        line_num += 1


def is_disabled(filename):
    lines = open(filename, "r").readlines()
    if lines[-1:].pop().__contains__("DISABLED"):
        print(f"******* {filename} *******\nTest disabled.")
        return True
    return False


def build(filename):
    directory = filename.split("/")[0]
    test_name = filename.split("/")[1].removesuffix(".cpp")
    output_name = f"{directory}/obj/{test_name}"
    lines = open(filename, "r").readlines()
    if lines[0].__contains__("BINMSAN COMPILE OPTIONS"):
        options = "-I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan " \
                  "-I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ " \
                  "-I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/ " \
                  "-L$BINMSAN_HOME/plugins_install " \
                  "-lbinmsan_lib"
        return subprocess.call(f"g++ {filename} -o {output_name} {options} >> {directory}/logs/{test_name}.txt 2>&1", shell=True)
    else:
        return subprocess.call(f"g++ {filename} -o {output_name} >> {directory}/logs/{test_name}.txt 2>&1", shell=True)


def sanitize(filename):
    directory = filename.split("/")[0]
    test_name = filename.split("/")[1].removesuffix(".cpp")
    options = "-k -l"
    if open(filename, "r").readlines().pop(1).__contains__("// HALT ON ERROR"):
        options = "-l"
    output_name = f"{directory}/obj/{test_name}"
    sanitized_name = f"{output_name}_sanitized"
    return subprocess.call(
        f"../binary-msan.sh {options} {output_name} {sanitized_name} >> {directory}/logs/{test_name}.txt 2>&1",
        #f"../binary-msan.sh {output_name} {sanitized_name} >> {directory}/logs/{test_name}.txt 2>&1",
        shell=True)


def run_test(filename):
    directory = filename.split("/")[0]
    test_name = filename.split("/")[1].removesuffix(".cpp")
    output_name = f"{directory}/obj/{test_name}"
    sanitized_name = f"{output_name}_sanitized"
    return subprocess.call(f"./{sanitized_name} >> {directory}/logs/{test_name}.txt 2>&1", shell=True)


def execute_test_case(file):
    if is_disabled(file):
        return
    exit_code = build(file)
    if exit_code != 0:
        print(f"******* {file} *******\n{RED}ERROR: Build failed.{END}")
        return
    exit_code = sanitize(file)
    if exit_code != 0:
        print(f"******* {file} *******\n{RED}ERROR: Sanitization failed.{END}")
        return
    run_test(file)
    verify_expected_output(file)


if __name__ == '__main__':
    # Verify python 3.9
    try:
        "test".removesuffix("t")
    except AttributeError:
        print("Please use at least Python version 3.9. Abort.")
        exit()

    subprocess.call(f"chmod +x {CLEAN_SCRIPT}", shell=True)
    subprocess.call(CLEAN_SCRIPT, shell=True)

    regex = ""
    if len(sys.argv) > 1:
        regex = sys.argv[1]
    current_wd = os.getcwd()
    directories = [name for name in os.listdir(current_wd)
                   if os.path.isdir(os.path.join(current_wd, name)) and name.__contains__("Tests")]

    files = []
    for directory in directories:
        path = current_wd + "/" + directory
        testfiles = [f for f in listdir(path) if isfile(join(directory, f))]
        for file in testfiles:
            file = f"{directory}/{file}"
            if not file.endswith(".cpp"):
                continue
            if regex != "":
                result = re.search(regex, file)
                if result is None:
                    continue
            files.append(file)
    print(f"Processing {len(files)} test case(s).")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(execute_test_case, files)
