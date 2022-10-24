import os
import pathlib
import subprocess
from os.path import join, isfile

TEST_DIRECTORY = os.getcwd() + "/../test"
EVAL_DIRECTORY = os.getcwd()
BIN_DIRECTORY = EVAL_DIRECTORY + "/bin"
SAN_DIRECTORY = EVAL_DIRECTORY + "/san"
ZIPRED_DIRECTORY = EVAL_DIRECTORY + "/zipr_san"

def get_test_sources():
    directories = [name for name in os.listdir(TEST_DIRECTORY)
                   if os.path.isdir(os.path.join(TEST_DIRECTORY, name)) and name.__contains__("Tests")]

    files = []
    for directory in directories:
        subtest_directory = TEST_DIRECTORY + "/" + directory
        testfiles = [f for f in os.listdir(subtest_directory) if isfile(join(subtest_directory, f))]
        for file in testfiles:
            if file.endswith(".cpp"):
                files.append(subtest_directory + "/" + file)
    return files


def get_regular_binaries(test_sources):
    binaries = [join(BIN_DIRECTORY, file) for file in os.listdir(BIN_DIRECTORY) if isfile(join(BIN_DIRECTORY, file))]
    # if len(binaries) <= 60:
    #     for test in test_sources:
    #         binaries.append(build(test))
    return binaries


def build(filename):
    test_name = filename.split("/")[-1].removesuffix(".cpp")
    output_name = f"{BIN_DIRECTORY}/{test_name}"
    lines = open(filename, "r").readlines()
    exit_code = 0
    if lines[0].__contains__("COMPILE OPTIONS"):
        options = lines[0].replace("// COMPILE OPTIONS: ", "").strip("\n")
        exit_code = subprocess.call(f"g++ {filename} -o {output_name} {options} > /dev/null", shell=True)
    else:
        exit_code = subprocess.call(f"g++ {filename} -o {output_name} > /dev/null", shell=True)
    if exit_code != 0:
        print(f"Building test case {test_name} failed.")
    else:
        return output_name


def measure_sanitization(filepath, with_binmsan: bool):
    file = filepath.split("/")[-1]
    if with_binmsan:
        pathlib.Path(SAN_DIRECTORY).mkdir(exist_ok=True)
        sanitize_command = f"time -p ../binary-msan.sh {filepath} {SAN_DIRECTORY}/{file}_san"
    else:
        try:
            dict(os.environ)["PSZ"]
        except KeyError:
            print("PSZ env variable not defined. Please run `source ../init.sh` and restart. Abort.")
            exit(1)
        pathlib.Path(ZIPRED_DIRECTORY).mkdir(exist_ok=True)
        sanitize_command = f"time -p $PSZ -c rida --step move_globals {filepath} {ZIPRED_DIRECTORY}/{file}_san"
    subprocess_return = subprocess.Popen(sanitize_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    stdout, stderr = subprocess_return.communicate()
    # Time with option -p outputs its measurement in seconds to stderr
    for line in stderr.split("\n"):
        if line.startswith("real"):
            time = line.replace("real ", "")
            return float(time)


def measure_instrumentation_time(binaries, with_binmsan : bool):
    results = {}
    for binary_path in binaries:
        sanitization_time = measure_sanitization(binary_path, with_binmsan)
        results[binary_path] = sanitization_time
    return results


# binmsan
def measure_run_time_performance(binmsanified_binaries):
    results = {}
    for binmsanified_binary in binmsanified_binaries:
        run_command = f"bash -i -c 'time {binmsanified_binary}'"
        env = {'TIMEFORMAT' : 'real %3R'}
        sum = 0
        runs = 10
        for i in range(runs):
            subprocess_return = subprocess.Popen(run_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, shell=True, text=True)
            stdout, stderr = subprocess_return.communicate()
            # Time with option -p outputs its measurement in seconds to stderr
            for line in stderr.split("\n"):
                if line.startswith("real"):
                    time = line.replace("real ", "")
                    sum += float(time)
        results[binmsanified_binary] = round((sum / runs), 3)
    return results




if __name__ == '__main__':
    # Get and build binaries
    test_sources = get_test_sources()
    pathlib.Path('bin').mkdir(exist_ok=True)
    binaries = get_regular_binaries(test_sources)

    # Instrumentation
    #sanitization_time_zipr = measure_instrumentation_time(binaries[0:2], with_binmsan=False)
    sanitization_time_binmsan_zipr = measure_instrumentation_time(binaries[0:2], with_binmsan=True)

    # Run-time performance
    binmsanified_binaries = [join(SAN_DIRECTORY, file) for file in os.listdir(SAN_DIRECTORY) if isfile(join(SAN_DIRECTORY, file))]
    print(binmsanified_binaries)
    print(measure_run_time_performance(binmsanified_binaries[0:2]))

