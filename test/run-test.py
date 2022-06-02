import subprocess

TEST_SCRIPT = "./test.sh"
GREEN = '\033[92m'
RED = '\033[91m'
END = '\033[0m'

def get_expected_output(filename):
    lines = open(filename, "r").readlines()
    return lines[-1:].pop().replace("// EXPECTED: ", "").strip("\n")


if __name__ == '__main__':
    testfiles = ["memToReg_64bit.cpp"]
    for file in testfiles:
        print(f"Test case ******* {file} *******")
        subprocess.call(TEST_SCRIPT + " " + file, shell=True)
        expected_output = get_expected_output(file)

        test = file.strip(".cpp").strip(".c") + ".txt"
        log_lines = open(f"logs/{test}", "r").readlines()

        line_num = 1
        for line in log_lines:
            if line_num == len(log_lines):
                print(f"{RED}ERROR: Expected output was not in logs/{test}. Expected: '{expected_output}'.{END}")
                break
            if expected_output in line:
                print(f"{GREEN}SUCCESS: Found expected output. Expected: '{expected_output}'.{END}")
                break
            line_num += 1

    # needed per test:
    # - cpp file to build
    # - specification of expected output

    # get all file names and per file:
    # create command to build
    # create command to sanitize
    # create command to run and log results
    # verify test logs against expected outcome

# expected output includes: "memToRegShadowCopy. MemAddress: . Shadow of reg is: "
