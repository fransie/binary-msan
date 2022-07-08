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


def get_expected_output(filename):
    lines = open(filename, "r").readlines()
    return lines[-1:].pop().replace("// EXPECTED: ", "").strip("\n")


def is_disabled(filename):
    lines = open(filename, "r").readlines()
    if lines[-1:].pop().__contains__("DISABLED"):
        print(f"******* {filename} *******\nTest disabled.")
        return True
    return False


def build(filename):
    test_name = filename.removesuffix(".cpp")
    output_name = f"obj/{test_name}"
    lines = open(filename, "r").readlines()
    if lines[0].__contains__("COMPILE OPTIONS"):
        options = lines[0].replace("// COMPILE OPTIONS: ", "").strip("\n")
        subprocess.call(f"g++ {filename} -o {output_name} {options} >> logs/{test_name}.txt 2>&1", shell=True)
    else:
        subprocess.call(f"g++ {filename} -o {output_name} >> logs/{test_name}.txt 2>&1", shell=True)
    return True


def sanitize(filename):
    test_name = filename.removesuffix(".cpp")
    output_name = f"obj/{test_name}"
    sanitized_name = f"{output_name}_sanitized"
    subprocess.call(
        f"$PSZ -c rida --step move_globals -c binmsan {output_name} {sanitized_name} >> logs/{test_name}.txt 2>&1",
        shell=True)


def run_test(filename):
    test_name = filename.removesuffix(".cpp")
    output_name = f"obj/{test_name}"
    sanitized_name = f"{output_name}_sanitized"
    return subprocess.call(f"./{sanitized_name} >> logs/{test_name}.txt 2>&1", shell=True)


def execute_test_case(file):
    if not file.endswith(".cpp"):
        return
    if regex != "":
        result = re.search(regex, file)
        if result is None:
            return
    if is_disabled(file):
        return
    build(file)
    sanitize(file)
    exit_code = run_test(file)
    if exit_code == 2:
        print(f"Run of sanitized {file} failed.")
        return

    expected_output = get_expected_output(file)
    log = file.removesuffix(".cpp") + ".txt"
    log_lines = open(f"logs/{log}", "r").readlines()

    line_num = 1
    for line in log_lines:
        if expected_output in line:
            print(f"******* {file} *******\n{GREEN}SUCCESS: Found expected output in logs/{log}. Expected: '{expected_output}'{END}")
            break
        if line_num == len(log_lines):
            print(f"******* {file} *******\n{RED}ERROR: Expected output was not in logs/{log}. Expected: '{expected_output}'{END}")
            break
        line_num += 1


if __name__ == '__main__':
    subprocess.call(CLEAN_SCRIPT, shell=True)

    regex = ""
    if len(sys.argv) > 1:
        regex = sys.argv[1]
    # TODO: fix absolute path
    dirs = [".", "MovHandlerTests"]
    for directory in dirs:
        testfiles = [f for f in listdir(f"/home/franzi/Documents/binary-msan/test/{directory}") if isfile(join(f"", f))]
        files = []
        for file in testfiles:
            files.append(directory + "/" + file)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(execute_test_case, files)
