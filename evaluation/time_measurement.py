import os
import sys
import pathlib
import subprocess
from enum import Enum
from os.path import join, isfile
import pandas as pd
from functools import reduce
from operator import add
import seaborn
from matplotlib import pyplot as plt
import matplotlib.patches as mpatches

EVAL_DIRECTORY = os.getcwd()
TEST_DIRECTORY = EVAL_DIRECTORY.removesuffix("evaluation") + "test"
BIN_DIRECTORY = EVAL_DIRECTORY + "/bin"
SAN_DIRECTORY = EVAL_DIRECTORY + "/san"
MSAN_DIRECTORY = EVAL_DIRECTORY + "/msan"
ZIPRED_DIRECTORY = EVAL_DIRECTORY + "/zipr_san"
TEST_FOLDERS = [name for name in os.listdir(TEST_DIRECTORY)
                if os.path.isdir(os.path.join(TEST_DIRECTORY, name)) and name.__contains__("Tests")]
INSTRUMENTED_LIBCXX_PATH = "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/llvmInstrumentedBuild"


class Tool(Enum):
    Memcheck = 1
    Dr_Memory = 2


class Compile_Type(Enum):
    Regular = 1
    MSan = 2


def get_env():
    env = dict(os.environ)
    env.update({'TIMEFORMAT': 'real %3R'})
    env.update({'LC_NUMERIC': 'en_US.UTF-8'})
    binmsan_home = env['BINMSAN_HOME']
    paths_to_add = f"{binmsan_home}/plugins_install:{INSTRUMENTED_LIBCXX_PATH}/lib'"
    try:
        ld_library_path = env['LD_LIBRARY_PATH']
        env.update({'LD_LIBRARY_PATH': f'{ld_library_path}:{paths_to_add}'})
    except KeyError:
        env.update({'LD_LIBRARY_PATH': f'{paths_to_add}'})
    return env


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
    test_cases_in_folder = [v for k, v in results.items()]
    average = reduce(add, test_cases_in_folder) / len(test_cases_in_folder)
    results["OVERALL-AVERAGE"] = round(average, 3)
    for folder in TEST_FOLDERS:
        test_cases_in_folder = [v for k, v in results.items() if k.startswith(folder)]
        average = reduce(add, test_cases_in_folder) / len(test_cases_in_folder)
        results[f"{folder}-AVERAGE"] = round(average, 3)


# Measure the build time of clang for binaries, either with or without MemorySanitizer.
def measure_build_time(test_sources, compile_type: Compile_Type):
    results = {}
    for binary_path in test_sources:
        folder_name = binary_path.split("/")[-2]
        test_name = binary_path.split("/")[-1].removesuffix(".cpp")
        output_name = f"{BIN_DIRECTORY}/{folder_name}-{test_name}"
        options = ""
        if compile_type == Compile_Type.MSan:
            options = f"-fsanitize=memory " \
                      f"-stdlib=libc++ " \
                      f"-L{INSTRUMENTED_LIBCXX_PATH}/lib " \
                      f"-lc++abi " \
                      f"-I{INSTRUMENTED_LIBCXX_PATH}/include " \
                      f"-I{INSTRUMENTED_LIBCXX_PATH}/include/c++/v1 " \
                      f"-Wl,-rpath,{INSTRUMENTED_LIBCXX_PATH}/lib "
            output_name = f"{MSAN_DIRECTORY}/{folder_name}-{test_name}"
        lines = open(binary_path, "r").readlines()
        if lines[0].__contains__("COMPILE OPTIONS"):
            options = options + lines[0].replace("// COMPILE OPTIONS: ", "").strip("\n")
        run_command = f"bash -i -c 'time clang++ {options} {binary_path} -o {output_name}'"
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
            sanitize_command = f"bash -i -c 'time ../binary-msan.sh {binary_path} {SAN_DIRECTORY}/{file}'"
        else:
            pathlib.Path(ZIPRED_DIRECTORY).mkdir(exist_ok=True)
            sanitize_command = f"bash -i -c 'time $PSZ -c rida {binary_path} {ZIPRED_DIRECTORY}/{file}'"
        subprocess_return = subprocess.Popen(sanitize_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env=get_env(),
                                             shell=True, text=True)
        stdout, stderr = subprocess_return.communicate()
        # Time outputs its measurement (s) to stderr
        for line in stderr.split("\n"):
            if line.startswith("real"):
                sanitization_time = line.replace("real ", "")
                results[file] = float(sanitization_time)
    append_averages(results)
    return results


# binmsan & msan
def measure_static_run_time_performance(binaries):
    results = {}
    for binary in binaries:
        run_command = f"bash -i -c 'time {binary}'"
        sum = 0
        runs = 10
        for i in range(runs):
            subprocess_return = subprocess.Popen(run_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 env=get_env(),
                                                 shell=True, text=True)
            stdout, stderr = subprocess_return.communicate()
            for line in stderr.split("\n"):
                if line.startswith("real"):
                    time = line.replace("real ", "")
                    sum += float(time)
        file = binary.split("/")[-1]
        results[file] = round((sum / runs), 3)
    append_averages(results)
    return results


# regular, memcheck and dr memory
def measure_dynamic_runtime_performance(binaries, tool: Tool):
    results = {}
    if tool == Tool.Memcheck:
        cmd = "valgrind --tool=memcheck --leak-check=no"
    elif tool == Tool.Dr_Memory:
        cmd = "drmemory -no_check_leaks -no_count_leaks --"
    else:
        print(f"Unknown tool {tool}. Abort.")
        exit(1)
    for binary in binaries:
        file = binary.split("/")[-1]
        run_command = f"bash -i -c 'time {cmd} {binary}'"
        sum = 0
        runs = 10
        for i in range(runs):
            subprocess_return = subprocess.Popen(run_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 env=get_env(),
                                                 shell=True, text=True)
            stdout, stderr = subprocess_return.communicate()
            for line in stderr.split("\n"):
                if line.startswith("real"):
                    time = line.replace("real ", "")
                    sum += float(time)
        results[file] = round((sum / runs), 3)
    append_averages(results)
    return results


def get_compile_and_sanitization_data():
    # Get source files
    test_sources = get_test_source_files()
    print(f"Start compilation and sanitization.")

    # Compilation: Clang vs. Clang & MSan
    build_time_clang = measure_build_time(test_sources, Compile_Type.Regular)
    build_time_clang_msan = measure_build_time(test_sources, Compile_Type.MSan)

    # Instrumentation: Zipr vs. Zipr & BinMSan
    binaries = [join(BIN_DIRECTORY, file) for file in os.listdir(BIN_DIRECTORY)]
    sanitization_time_binmsan_zipr = measure_sanitization_time(binaries, with_binmsan=True)
    sanitization_time_zipr = measure_sanitization_time(binaries, with_binmsan=False)

    dataframe = pd.DataFrame.from_dict({
        'clang': build_time_clang,
        'clang-msan': build_time_clang_msan,
        'zipr': sanitization_time_zipr,
        'zipr-binmsan': sanitization_time_binmsan_zipr,
    })
    print(f"Finished compilation and sanitization.")
    return dataframe.sort_index()


def get_run_time_performance():
    print(f"Start run-time performance measurement.")

    # get binaries
    binaries = [join(BIN_DIRECTORY, file) for file in os.listdir(BIN_DIRECTORY) if isfile(join(BIN_DIRECTORY, file))]
    msanified_binaries = [join(MSAN_DIRECTORY, file) for file in os.listdir(MSAN_DIRECTORY) if
                          isfile(join(MSAN_DIRECTORY, file))]
    zipred_binaries = [join(ZIPRED_DIRECTORY, file) for file in os.listdir(ZIPRED_DIRECTORY) if
                       isfile(join(ZIPRED_DIRECTORY, file))]
    binmsanified_binaries = [join(SAN_DIRECTORY, file) for file in os.listdir(SAN_DIRECTORY) if
                             isfile(join(SAN_DIRECTORY, file))]

    # get performance
    baseline_run_time = measure_static_run_time_performance(binaries)
    msan_run_time = measure_static_run_time_performance(msanified_binaries)
    zipred_run_time = measure_static_run_time_performance(zipred_binaries)
    binmsan_run_time = measure_static_run_time_performance(binmsanified_binaries)
    memcheck_run_time = measure_dynamic_runtime_performance(binaries, Tool.Memcheck)
    drmemory_run_time = measure_dynamic_runtime_performance(binaries, Tool.Dr_Memory)

    # return dataframe
    dataframe = pd.DataFrame.from_dict({
        'baseline': baseline_run_time,
        'msan': msan_run_time,
        'zipr': zipred_run_time,
        'binmsan': binmsan_run_time,
        'dr memory': drmemory_run_time,
        'memcheck': memcheck_run_time,
    })
    print(f"Finished run-time performance measurement.")
    return dataframe.sort_index()


def compare_zipr_runtime(row):
    if row['zipr'] > row['baseline']:
        return "baseline"
    elif row['zipr'] == row['baseline']:
        return "equal"
    else:
        return "zipr"


if __name__ == '__main__':
    # if len(sys.argv) > 1 and sys.argv[1] == 'clean':
    #     for dir in [BIN_DIRECTORY, MSAN_DIRECTORY, SAN_DIRECTORY, ZIPRED_DIRECTORY]:
    #         for file in os.listdir(dir):
    #             os.remove(os.path.join(dir, file))
    #
    # # Preparations.
    # pathlib.Path('bin').mkdir(exist_ok=True)
    # pathlib.Path('msan').mkdir(exist_ok=True)
    # pathlib.Path('san').mkdir(exist_ok=True)
    # pathlib.Path('zipr_san').mkdir(exist_ok=True)
    # pathlib.Path('results').mkdir(exist_ok=True)
    # try:
    #     dict(os.environ)["PSZ"]
    # except KeyError:
    #     print("PSZ env variable not defined. Please run `source ../init.sh` and restart. Abort.")
    #     exit(1)
    # exit_code = subprocess.call("which drmemory > /dev/null", shell=True)
    # exit_code += subprocess.call("which valgrind > /dev/null", shell=True)
    # if exit_code != 0:
    #     print("Please make sure that the executables valgrind and drmemory are available. Abort.")
    #     exit(1)
    #
    # print(f"Processing {len(get_test_source_files())} test cases.")
    #
    # # Compilation and sanitization time measurement
    result_path = EVAL_DIRECTORY + "/results"
    # df = get_compile_and_sanitization_data()
    # df.to_csv(f"{result_path}/compile_sanitize_times.csv", sep=',', index_label="test case")
    #
    # # Run-time performance measurement
    # df = get_run_time_performance()
    # df.to_csv(f"{result_path}/run_time_performances.csv", sep=',', index_label="test case")

    # MSan und BinMSan preparations plot
    # plt.figure()
    # df = pd.read_csv(f"{result_path}/compile_sanitize_times.csv", index_col='test case')
    # data = {'Tool': ['MemorySanitizer','Zipr + BinMSan'],
    #         'Instrumentation time (s)': [df.loc['OVERALL-AVERAGE']['clang-msan'],df.loc['OVERALL-AVERAGE']['zipr-binmsan']]}
    # frame = pd.DataFrame(data=data)
    # seaborn.set_theme(style="white", font="cochineal", font_scale=1.3)
    # barplot1 = seaborn.barplot(data=frame, x='Tool', y='Instrumentation time (s)', color="#BDD7EE")
    # data = {'Tool': ['MemorySanitizer','BinMSan'],
    #         'Instrumentation time (s)': [df.loc['OVERALL-AVERAGE']['clang'],df.loc['OVERALL-AVERAGE']['zipr']]}
    # frame = pd.DataFrame(data=data)
    # barplot2 = seaborn.barplot(data=frame, x='Tool', y='Instrumentation time (s)', color='#00457D')
    # barplot1.set_xlabel("")
    # barplot1.set_ylabel("Average instrumentation time (s)")
    # top_bar = mpatches.Patch(color='#BDD7EE', label='Sanitiser')
    # bottom_bar = mpatches.Patch(color='#00457D', label='Base tool')
    # plt.legend(handles=[top_bar, bottom_bar])
    # seaborn.despine()
    # plt.savefig(f"{result_path}/instrumentation_time.pdf")
    # plt.close()
    #
    # # Run-time plot
    # df = pd.read_csv(f"{result_path}/run_time_performances.csv", index_col='test case')
    # data = {'Tool': ['Baseline','MemorySanitizer','BinMSan','MemCheck','Dr. Memory'],
    #         'Run-time (s)': [df.loc['OVERALL-AVERAGE']['baseline'],df.loc['OVERALL-AVERAGE']['msan'],df.loc['OVERALL-AVERAGE']['binmsan'],df.loc['OVERALL-AVERAGE']['memcheck'], df.loc['OVERALL-AVERAGE']['dr memory']]}
    # frame = pd.DataFrame(data=data)
    # plt.figure(figsize=(8, 9))
    # barplot = seaborn.barplot(data=frame, x='Tool', y='Run-time (s)', color="#00457D")
    # barplot.set_xticklabels(barplot.get_xticklabels(), rotation=30, ha="right")
    # barplot.set_xlabel("")
    # barplot.set_ylabel("Average run-time (s)")
    # seaborn.despine()
    # fig = barplot.get_figure()
    # fig.savefig(f"{result_path}/run_time.pdf")
    #
    # Overhead of Zipr:
    df = pd.read_csv(f"{result_path}/run_time_performances.csv", index_col='test case')
    df.drop(columns=['msan', 'binmsan', 'dr memory', 'memcheck'], inplace=True)
    df = df[df.index.str.contains("AVERAGE") == False]
    df['faster tool'] = df.apply(lambda row: compare_zipr_runtime(row), axis=1)
    df.sort_values('faster tool', inplace=True)
    df.value_counts(df['faster tool']).to_csv(f"{result_path}/zipr_vs_baseline.csv")