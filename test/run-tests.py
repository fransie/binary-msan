import subprocess
from os import listdir
from os.path import isfile, join

TEST_SCRIPT = "./test.sh"
CLEAN_SCRIPT = "./clean.sh"
GREEN = '\033[92m'
RED = '\033[91m'
END = '\033[0m'

def get_expected_output(filename):
    lines = open(filename, "r").readlines()
    return lines[-1:].pop().replace("// EXPECTED: ", "").strip("\n")


if __name__ == '__main__':
    subprocess.call(CLEAN_SCRIPT, shell=True)
    # TODO: fix absolute path
    testfiles = [f for f in listdir("/home/franzi/Documents/binary-msan/test") if isfile(join("", f))]
    for file in testfiles:
        if not file.endswith(".cpp"):
            continue
        print(f"Test case ******* {file} *******")
        subprocess.call(TEST_SCRIPT + " " + file, shell=True)
        expected_output = get_expected_output(file)

        log = file.removesuffix(".cpp") + ".txt"
        log_lines = open(f"logs/{log}", "r").readlines()

        line_num = 1
        for line in log_lines:
            if line_num == len(log_lines):
                print(f"{RED}ERROR: Expected output was not in logs/{log}. Expected: '{expected_output}'{END}")
                break
            if expected_output in line:
                print(f"{GREEN}SUCCESS: Found expected output in logs/{log}. Expected: '{expected_output}'{END}")
                break
            line_num += 1