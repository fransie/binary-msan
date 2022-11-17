import os
import sys
import pathlib
import subprocess
from enum import Enum
from os.path import join, isfile
import pandas as pd
import seaborn
from matplotlib import pyplot as plt
import matplotlib.patches as mpatches

EVAL_DIRECTORY = os.getcwd()
TEST_DIRECTORY = EVAL_DIRECTORY.removesuffix("evaluation") + "test"
BIN_DIRECTORY = EVAL_DIRECTORY + "/bin"
SAN_DIRECTORY = EVAL_DIRECTORY + "/san"
MSAN_DIRECTORY = EVAL_DIRECTORY + "/msan"
ZIPRED_DIRECTORY = EVAL_DIRECTORY + "/zipr_san"
RESULT_PATH = EVAL_DIRECTORY + "/results"
TEST_FOLDERS = [name for name in os.listdir(TEST_DIRECTORY)
                if os.path.isdir(os.path.join(TEST_DIRECTORY, name)) and name.__contains__("Tests")]
RUNTIME_TEST_FOLDERS = ["PropagationTests", "SinkTests"]
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
    files = []
    for directory in TEST_FOLDERS:
        subtest_directory = TEST_DIRECTORY + "/" + directory
        testfiles = [f for f in os.listdir(subtest_directory) if isfile(join(subtest_directory, f))]
        for file in testfiles:
            if file.endswith(".cpp"):
                files.append(subtest_directory + "/" + file)
    return files


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
                      f"-fsanitize-recover=memory " \
                      f"-fsanitize-memory-track-origins=0 " \
                      f"-stdlib=libc++ " \
                      f"-L{INSTRUMENTED_LIBCXX_PATH}/lib " \
                      f"-lc++abi " \
                      f"-I{INSTRUMENTED_LIBCXX_PATH}/include " \
                      f"-I{INSTRUMENTED_LIBCXX_PATH}/include/c++/v1 " \
                      f"-Wl,-rpath,{INSTRUMENTED_LIBCXX_PATH}/lib "
            output_name = f"{MSAN_DIRECTORY}/{folder_name}-{test_name}"
        lines = open(binary_path, "r").readlines()
        if lines[0].__contains__("BINMSAN COMPILE OPTIONS"):
            options = options + "-I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/msan " \
                                "-I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/include/sanitizer/ " \
                                "-I$BINMSAN_HOME/llvm_shared_msan_lib/compiler-rt/lib/ " \
                                "-L$BINMSAN_HOME/plugins_install " \
                                "-lbinmsan_lib " \
                                "-Wl,-rpath,$BINMSAN_HOME/plugins_install "
        run_command = f"bash -i -c 'time clang++ {options} {binary_path} -o {output_name}'"
        subprocess_return = subprocess.Popen(run_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=get_env(),
                                             shell=True, text=True)
        stdout, stderr = subprocess_return.communicate()
        for line in stderr.split("\n"):
            if line.startswith("real"):
                build_time = line.replace("real ", "")
                results[f"{folder_name}-{test_name}"] = float(build_time)
    return results


# Measure the sanitization/rewriting time of zipr, either with or without binmsan.
def measure_sanitization_time(binaries, with_binmsan: bool):
    results = {}
    for binary_path in binaries:
        file = binary_path.split("/")[-1]
        if with_binmsan:
            pathlib.Path(SAN_DIRECTORY).mkdir(exist_ok=True)
            sanitize_command = f"bash -i -c 'time ../binary-msan.sh -k {binary_path} {SAN_DIRECTORY}/{file}'"
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
    return results


def get_compile_and_sanitization_data():
    # Get source files
    test_sources = get_test_source_files()
    print(f"Start compilation and sanitization of {len(get_test_source_files())} binaries.")

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
    print(f"Start runtime performance measurement.")

    # get binaries
    binaries = [join(BIN_DIRECTORY, file) for file in os.listdir(BIN_DIRECTORY)
                if isfile(join(BIN_DIRECTORY, file)) and
                (file.__contains__(RUNTIME_TEST_FOLDERS[0]) or file.__contains__(RUNTIME_TEST_FOLDERS[1]))]
    msanified_binaries = [join(MSAN_DIRECTORY, file) for file in os.listdir(MSAN_DIRECTORY) if
                          isfile(join(MSAN_DIRECTORY, file)) and
                          (file.__contains__(RUNTIME_TEST_FOLDERS[0]) or file.__contains__(RUNTIME_TEST_FOLDERS[1]))]
    zipred_binaries = [join(ZIPRED_DIRECTORY, file) for file in os.listdir(ZIPRED_DIRECTORY) if
                       isfile(join(ZIPRED_DIRECTORY, file)) and
                       (file.__contains__(RUNTIME_TEST_FOLDERS[0]) or file.__contains__(RUNTIME_TEST_FOLDERS[1]))]
    binmsanified_binaries = [join(SAN_DIRECTORY, file) for file in os.listdir(SAN_DIRECTORY) if
                             isfile(join(SAN_DIRECTORY, file)) and
                             (file.__contains__(RUNTIME_TEST_FOLDERS[0]) or file.__contains__(RUNTIME_TEST_FOLDERS[1]))]

    print(f"Binaries: {len(binaries)}, Msanified binaries: {len(msanified_binaries)},"
          f" Zipred binaries: {len(zipred_binaries)}, Binmsanified binaries: {len(binmsanified_binaries)}.")

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
    print(f"Finished runtime performance measurement.")
    return dataframe.sort_index()


def compare_zipr_runtime(row):
    if row['zipr'] > row['baseline']:
        return "baseline"
    elif row['zipr'] == row['baseline']:
        return "equal"
    else:
        return "zipr"


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'clean':
        for dir in [BIN_DIRECTORY, MSAN_DIRECTORY, SAN_DIRECTORY, ZIPRED_DIRECTORY]:
            for file in os.listdir(dir):
                os.remove(os.path.join(dir, file))

    # Preparations.
    pathlib.Path('bin').mkdir(exist_ok=True)
    pathlib.Path('msan').mkdir(exist_ok=True)
    pathlib.Path('san').mkdir(exist_ok=True)
    pathlib.Path('zipr_san').mkdir(exist_ok=True)
    pathlib.Path('results').mkdir(exist_ok=True)
    try:
        dict(os.environ)["PSZ"]
    except KeyError:
        print("PSZ env variable not defined. Please run `source ../init.sh` and restart. Abort.")
        exit(1)
    exit_code = subprocess.call("which drmemory > /dev/null", shell=True)
    exit_code += subprocess.call("which valgrind > /dev/null", shell=True)
    if exit_code != 0:
        print("Please make sure that the executables valgrind and drmemory are available. Abort.")
        exit(1)

    # Compilation and sanitization time measurement
    df = get_compile_and_sanitization_data()
    df.to_csv(f"{RESULT_PATH}/compile_sanitize_times.csv", sep=',', index_label="test case")
    # Runtime performance measurement
    df = get_run_time_performance()
    df.to_csv(f"{RESULT_PATH}/run_time_performances.csv", sep=',', index_label="test case")

    # MSan und BinMSan preparations plot
    plt.figure()
    df = pd.read_csv(f"{RESULT_PATH}/compile_sanitize_times.csv", index_col='test case')
    print(f"Compilation and sanitisation:\n{df.describe()}\n")
    data = {'Tool': ['MemorySanitizer', 'Zipr + BinMSan'],
            'Instrumentation time (s)': [df['clang-msan'].mean(), df['zipr-binmsan'].mean()]}
    frame = pd.DataFrame(data=data)
    seaborn.set_theme(style="ticks", font="cochineal", font_scale=1.3)
    barplot1 = seaborn.barplot(data=frame, x='Tool', y='Instrumentation time (s)', color="#BDD7EE")
    barplot1.tick_params(bottom=False)
    data = {'Tool': ['MemorySanitizer', 'BinMSan'],
            'Instrumentation time (s)': [df['clang'].mean(), df['zipr'].mean()]}
    frame = pd.DataFrame(data=data)
    barplot2 = seaborn.barplot(data=frame, x='Tool', y='Instrumentation time (s)', color='#00457D')
    barplot2.tick_params(bottom=False)
    barplot1.set_xlabel("")
    barplot1.set_ylabel("Mean instrumentation time (s)")
    top_bar = mpatches.Patch(color='#BDD7EE', label='Sanitiser')
    bottom_bar = mpatches.Patch(color='#00457D', label='Base tool')
    plt.legend(handles=[top_bar, bottom_bar])
    seaborn.despine()
    plt.savefig(f"{RESULT_PATH}/instrumentation_time.pdf")
    plt.close()

    # Runtime plot
    df = pd.read_csv(f"{RESULT_PATH}/run_time_performances.csv", index_col='test case')
    print(f"Runtime performance:\n{df.describe()}\n")
    baseline = df['baseline'].mean()
    data = {'Tool': ['Baseline', 'MemorySanitizer', 'BinMSan', 'Memcheck', 'Dr. Memory'],
            'Mean runtime (s)': [baseline, df['msan'].mean(), df['binmsan'].mean(),
                                    df['memcheck'].mean(), df['dr memory'].mean()]}
    frame = pd.DataFrame(data=data)
    frame['Overhead factor'] = frame['Mean runtime (s)'] / baseline
    print(f"Mean overhead:\n{frame}\n")
    plt.figure(figsize=(8, 9))
    barplot1 = seaborn.barplot(data=frame, x='Tool', y='Mean runtime (s)', color=None)
    barplot1.tick_params(bottom=False)
    barplot1.set_xlabel("")
    ax2 = plt.twinx()
    barplot2 = seaborn.barplot(data=frame, x='Tool', y='Overhead factor', color="#00457D", ax=ax2)
    barplot2.set_xlabel("")
    barplot2.set_ylabel("Overhead factor")
    barplot2.tick_params(bottom=False)
    seaborn.despine(right=False)
    fig = barplot2.get_figure()
    fig.savefig(f"{RESULT_PATH}/run_time.pdf")

    # File size
    frame = pd.DataFrame(index=['Clang', 'BinMSan', 'MSan'])
    files = [f for f in os.listdir(BIN_DIRECTORY) if isfile(join(BIN_DIRECTORY, f))]
    for file in files:
        row = [os.stat(join(BIN_DIRECTORY, file)).st_size / 1024,
               os.stat(join(SAN_DIRECTORY, file)).st_size / 1024,
               os.stat(join(MSAN_DIRECTORY, file)).st_size / 1024]
        frame[file] = row
    frame.to_csv(f"{RESULT_PATH}/file_size.csv", sep=',')
    print(f"Mean file size:\n{frame.mean(axis='columns')}\n")
    print(f"Median file size:\n{frame.median(axis='columns')}")
