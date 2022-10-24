import concurrent.futures
import os
import subprocess
from os.path import isfile, join

RED = '\033[91m'
END = '\033[0m'


def count_instructions(binary):
    path = binary[0]
    filename = binary[1]
    output_file = f"{os.getcwd()}/{path}/counts/{filename}"
    exitcode = subprocess.call(
        f"./counter.sh {path}/binaries/{filename} {output_file} > {path}/logs/{filename}.log 2>&1",
        shell=True)
    if exitcode == 0:
        os.remove(f"{path}/binaries/{filename}_san")
        print(f"Finished {binary}")
    else:
        print(f"{RED}Instruction counting of {path}/binaries/{filename} failed! See log: {path}/logs/{filename}.log{END}")


def count(directory):
    bin_path = directory + "/binaries"
    binaries = []
    for name in [f for f in os.listdir(bin_path) if isfile(join(bin_path, f))]:
        binaries.append([directory, name])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(count_instructions, binaries)


def get_all_used_instructions(directory):
    # cat * | sort | uniq > ../list_of_instructions_used_in_coreutils.txt
    subprocess.call(
        f"cat {directory}/counts/* | sort | uniq > {directory}/results/list_of_instructions_used.txt",
        shell=True)


def analyse_directory(directory):
    count(directory)
    get_all_used_instructions(directory)


if __name__ == '__main__':
    directories = [ "binutils", "coreutils", "findutils"]
    for directory in directories:
        analyse_directory(directory)
