import os
import pathlib
import subprocess
from enum import Enum
from os.path import join, isfile
import pandas as pd
from functools import reduce
from operator import add

TEST_DIRECTORY = os.getcwd().removesuffix("evaluation") + "test"
EVAL_DIRECTORY = os.getcwd()
BIN_DIRECTORY = EVAL_DIRECTORY + "/bin"
SAN_DIRECTORY = EVAL_DIRECTORY + "/san"
MSAN_DIRECTORY = EVAL_DIRECTORY + "/msan"
ZIPRED_DIRECTORY = EVAL_DIRECTORY + "/zipr_san"
TEST_FOLDERS = [name for name in os.listdir(TEST_DIRECTORY)
                if os.path.isdir(os.path.join(TEST_DIRECTORY, name)) and name.__contains__("Tests")]


class Tool(Enum):
    Regular = 1
    Memcheck = 2
    Dr_Memory = 3


class Compile(Enum):
    Regular = 1
    MSan = 2


def get_env():
    e = dict(os.environ)
    e.update({'TIMEFORMAT': 'real %3R'})
    e.update({'LC_NUMERIC': 'en_US.UTF-8'})
    return e


def get_test_source_files():
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


def append_averages(results):
    for folder in ["ChainingTests", "StackVariableHandlerTests"]:
    #for folder in TEST_FOLDERS:
        test_cases_in_folder = [v for k, v in results.items() if k.startswith(folder)]
        average = reduce(add, test_cases_in_folder) / len(test_cases_in_folder)
        results[f"{folder}-AVERAGE"] = average


# Measure the build time of clang for binaries, either with or without MemorySanitizer.
def measure_build_time(test_sources, compile_type: Compile):
    results = {}
    for binary_path in test_sources:
        folder_name = binary_path.split("/")[-2]
        test_name = binary_path.split("/")[-1].removesuffix(".cpp")
        output_name = f"{BIN_DIRECTORY}/{folder_name}-{test_name}"
        options = ""
        if compile_type == Compile.MSan:
            options = "-fsanitize=memory "
            output_name = f"{MSAN_DIRECTORY}/{folder_name}-{test_name}"
        lines = open(binary_path, "r").readlines()
        if lines[0].__contains__("COMPILE OPTIONS"):
            options = options + lines[0].replace("// COMPILE OPTIONS: ", "").strip("\n")
        run_command = f"bash -i -c 'time clang++ {binary_path} -o {output_name} {options}'"
        subprocess_return = subprocess.Popen(run_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=get_env(),
                                             shell=True, text=True)
        stdout, stderr = subprocess_return.communicate()
        for line in stderr.split("\n"):
            if line.startswith("real"):
                build_time = line.replace("real ", "")
                results[f"{folder_name}-{test_name}"] = float(build_time)
    append_averages(results)
    return results


# Measure the sanitization/rewriting time of zipr, either with or without binmsan.
def measure_sanitization_time(binaries, with_binmsan: bool):
    results = {}
    for binary_path in binaries:
        file = binary_path.split("/")[-1]
        if with_binmsan:
            pathlib.Path(SAN_DIRECTORY).mkdir(exist_ok=True)
            sanitize_command = f"bash -i -c 'time ../binary-msan.sh {binary_path} {SAN_DIRECTORY}/{file}_san'"
        else:
            try:
                dict(os.environ)["PSZ"]
            except KeyError:
                print("PSZ env variable not defined. Please run `source ../init.sh` and restart. Abort.")
                exit(1)
            pathlib.Path(ZIPRED_DIRECTORY).mkdir(exist_ok=True)
            sanitize_command = f"bash -i -c 'time $PSZ -c rida {binary_path} {ZIPRED_DIRECTORY}/{file}_san'"
        subprocess_return = subprocess.Popen(sanitize_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env=get_env(),
                                             shell=True, text=True)
        stdout, stderr = subprocess_return.communicate()
        # Time outputs its measurement in seconds to stderr
        for line in stderr.split("\n"):
            if line.startswith("real"):
                sanitization_time = line.replace("real ", "")
                results[file] = float(sanitization_time)
    append_averages(results)
    return results


# binmsan & msan
def measure_run_time_performance(binmsanified_binaries):
    results = {}
    for binmsanified_binary in binmsanified_binaries:
        run_command = f"bash -i -c 'time {binmsanified_binary}'"
        sum = 0
        runs = 10
        for i in range(runs):
            subprocess_return = subprocess.Popen(run_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 env=get_env(),
                                                 shell=True, text=True)
            stdout, stderr = subprocess_return.communicate()
            # Time outputs its measurement in seconds to stderr
            for line in stderr.split("\n"):
                if line.startswith("real"):
                    time = line.replace("real ", "")
                    sum += float(time)
        results[binmsanified_binary] = round((sum / runs), 3)
    return results




if __name__ == '__main__':
    # Prepare folders
    pathlib.Path('bin').mkdir(exist_ok=True)
    pathlib.Path('msan').mkdir(exist_ok=True)

    # Get source files
    test_sources = get_test_source_files()[0:2] + [get_test_source_files()[-1]]

    # Compilation: Clang vs. Clang & MSan
    build_time_clang = measure_build_time(test_sources, Compile.Regular)
    build_time_clang_msan = measure_build_time(test_sources, Compile.MSan)

    # Instrumentation: Zipr vs. Zipr & BinMSan
    binaries = [join(BIN_DIRECTORY, file) for file in os.listdir(BIN_DIRECTORY)]
    sanitization_time_binmsan_zipr = measure_sanitization_time(binaries, with_binmsan=True)
    sanitization_time_zipr = measure_sanitization_time(binaries, with_binmsan=False)

    build_and_sanitize_time_binmsan = dict()
    for test, result in sanitization_time_zipr.items():
        build_time = build_time_clang[test]
        sanitization_time = sanitization_time_binmsan_zipr[test]
        build_and_sanitize_time_binmsan[test] = build_time + sanitization_time

    dataframe = pd.DataFrame.from_dict({
        'clang': build_time_clang,
        'clang-msan': build_time_clang_msan,
        'zipr': sanitization_time_zipr,
        'zipr-binmsan': sanitization_time_binmsan_zipr,
        'clang+binmsan': build_and_sanitize_time_binmsan
    })
    df = dataframe.sort_index()

    #
    # # binmsanified_binaries = [join(SAN_DIRECTORY, file) for file in os.listdir(SAN_DIRECTORY) if isfile(join(SAN_DIRECTORY, file))]
    #
    # # Run-time performance
    # # msan_res = measure_run_time_performance(binmsanified_binaries)
    # reg_res = measure_dynamic_runtime_performance(binaries,Tool.Regular)
    # memcheck_res = measure_dynamic_runtime_performance(binaries, Tool.Memcheck)
    # dr_res = measure_dynamic_runtime_performance(binaries, Tool.Dr_Memory)
    #
    # print("REGULAR:")
    # print(reg_res)
    # print("Memcheck:")
    # print(memcheck_res)
    # print("Dr Memory:")
    # print(dr_res)

    # Persist results