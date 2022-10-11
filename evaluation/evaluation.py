# How many distinct instructions does a binary have?
# binary - name | number of distinct instructions - check

# Which instructions are used in all the coreutils?
# list of instructions

# In how many binaries does an instruction appear? -> Order in which to instrument.
# instruction | number of binaries it appears in | list of binaries it appears in

# How many binaries could I instrument if the next x instructions (in order) were ready?
# x instructions | number of binaries


# 1: get all the instructions that a binary uses. Capstone?

# 2: Store binary and the name of distinct mnemonics, maybe in an array and write to a csv
import concurrent.futures
import csv
import os
import subprocess
from os.path import isfile, join


def count_instructions(binary):
    directory = os.getcwd() + "/" + binary[0]
    filename = binary[1]
    subprocess.call(
        f"./counter.sh {directory}/{filename} {directory}/counts/{filename} >> {directory}/logs/{filename}.log 2>&1 && rm {directory}/{filename}_san",
        shell=True)
    print(f"Finished {binary}")


def count(dirname):
    dir = dirname
    binaries = []
    for binary in [f for f in os.listdir(dir) if isfile(join(dir, f))]:
        binaries.append([dir, binary])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(count_instructions, binaries)


def find_distinct_instructions_per_binary(binary):
    dir = binary[0]
    filename = binary[1]
    with open(f"{dir}/counts/{filename}.txt", 'r') as counts_file:
        num_lines = sum(1 for line in counts_file)
    with open(f"{dir}/distinct_instructions.csv", "a") as myfile:
        myfile.write(f"{filename}, {num_lines}\n")


def find_distinct_instructions_in_directory(dirname):
    dir = dirname
    binaries = []
    for binary in [f for f in os.listdir(dir) if isfile(join(dir, f))]:
        binaries.append([dir, binary])
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(find_distinct_instructions_per_binary, binaries)


def find_instruction_appearances():
    # remove result file from last run
    os.remove("static-coreutils/instruction_appearances.csv")
    os.remove("static-coreutils/instruction_appearances_count.csv")
    with open("static-coreutils/list_of_instructions_used_in_coreutils.txt", 'r') as list_of_instructions:
        for mnemonic in list_of_instructions:
            mnemonic = mnemonic.replace("\n", "")
            dir = "static-coreutils/counts"
            for file in [f for f in os.listdir(dir) if isfile(join(dir, f))]:
                with open(f"static-coreutils/counts/{file}", 'r') as instructions_file:
                    for line in instructions_file:
                        if line.find(mnemonic) != -1:
                            with open("static-coreutils/instruction_appearances.csv", "a") as myfile:
                                myfile.write(f"{mnemonic}, {file}\n")
                            break
    with open("static-coreutils/list_of_instructions_used_in_coreutils.txt", 'r') as list_of_instructions:
        for mnemonic in list_of_instructions:
            mnemonic = mnemonic.replace("\n", "")
            count = 0
            with open("static-coreutils/instruction_appearances.csv", "r") as appearances:
                for line in appearances:
                    if line.startswith(mnemonic + ","):
                        count += 1
            with open("static-coreutils/instruction_appearances_count.csv", "a") as myfile:
                myfile.write(f"{mnemonic},{count}\n")


def order_instructions_bases_on_num_of_appearances():
    entries = []
    with open("static-coreutils/instruction_appearances_count.csv", "r") as appearances_count:
        reader = csv.reader(appearances_count, delimiter=',')
        for row in reader:
            entries.append([row[0], int(row[1])])
    entries.sort(key=lambda row: (row[1]), reverse=False)
    with open("static-coreutils/instructions_ordered_by_appearance.csv", "a") as myfile:
        for entry in entries:
            myfile.write(f"{entry[0]},{entry[1]}\n")


if __name__ == '__main__':
    # count("static-coreutils"):
    # get_distinct_instructions("static-coreutils")
    # command line in dir static-coreutils/counts: cat * | sort | uniq > ../list_of_instructions_used_in_coreutils.txt
    find_instruction_appearances()
    order_instructions_bases_on_num_of_appearances()
