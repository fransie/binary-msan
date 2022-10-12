import concurrent.futures
import os
import subprocess
from os.path import isfile, join

RED = '\033[91m'
END = '\033[0m'


def count_instructions(binary):
    path = binary[0]
    filename = binary[1]
    exitcode = subprocess.call(
        f"./counter.sh {path}/{filename} {path}/counts/{filename} > {path}/logs/{filename}.log 2>&1",
        shell=True)
    if exitcode == 0:
        os.remove(f"{path}/{filename}_san")
        print(f"Finished {binary}")
    else:
        print(f"{RED}Instruction counting of {path}/{filename} failed! See log: {path}/logs/{filename}.log{END}")


def count(directory):
    binaries = []
    for name in [f for f in os.listdir(directory) if isfile(join(directory, f))]:
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
    directory = "static-coreutils"
    analyse_directory(directory)
