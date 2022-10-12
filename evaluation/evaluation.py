import copy
import os
from os.path import isfile, join
import pandas
import seaborn
from typing import List
from matplotlib import font_manager, pyplot as plt


class Instruction:
    def __init__(self, mnemonic, binaries: list):
        self.mnemonic = mnemonic
        self.occurs_in = []
        self.populate_instruction(binaries)

    def populate_instruction(self, binaries: list):
        for binary in binaries:
            if self.mnemonic in binary.mnemonics:
                self.occurs_in.append(binary.filename)


class Binary:
    def __init__(self, name, path):
        self.filename = name
        self.path = path
        self.mnemonics = self.get_mnemonics()
        self.distinct_instructions = len(self.mnemonics)

    def get_mnemonics(self):
        mnemonics = set(())
        with open(f"{self.path}/counts/{self.filename}.txt", 'r') as counts_file:
            for line in counts_file:
                line = line.replace("\n", "")
                mnemonics.add(line)
        return mnemonics

    def is_ready_with(self, instrumented_mnemonics: List[Instruction]):
        instrumented = [ins.mnemonic for ins in instrumented_mnemonics]
        for instruction in self.mnemonics:
            if instruction not in instrumented:
                return False
        return True


class Combination:
    def __init__(self, instrumented_mnemonics: List[Instruction], binaries: List[Binary]):
        self.instrumented_instructions = instrumented_mnemonics
        self.binaries_ready = self.get_ready_binaries(binaries)
        self.num_instrumented = len(self.instrumented_instructions)
        self.num_binaries = len(self.binaries_ready)

    def get_ready_binaries(self, binaries):
        ready_binaries = []
        for binary in binaries:
            if binary.is_ready_with(self.instrumented_instructions):
                ready_binaries.append(binary)
        return ready_binaries


def get_binaries_in_directory(path):
    binaries = []
    for filename in [f for f in os.listdir(path) if isfile(join(path, f))]:
        binaries.append(Binary(filename, path))
    return binaries


def get_instructions_in_directory(path, binaries):
    instructions = []
    with open(f"{path}/results/list_of_instructions_used.txt", 'r') as instructions_file:
        for mnemonic in instructions_file:
            mnemonic = mnemonic.replace("\n", "")
            instructions.append(Instruction(mnemonic, binaries))
    return instructions


def int_to_category(number):
    x = int(number / 10) * 10
    y = x + 9
    return f"{x}-{y}"


if __name__ == '__main__':
    path = "static-coreutils"

    # Answers:
    # - How many distinct instructions does a binary have?  -> binary.distinct_instructions
    # - Which instructions are used in all the coreutils?   -> [ins.mnemonic for ins in instrumented_mnemonics]
    # - In how many binaries does an instruction appear?    -> instruction.occurs_in
    binaries = get_binaries_in_directory(path)
    instructions = get_instructions_in_directory(path, binaries)

    # Answers:
    # - In which order should the next instructions be instrumented based on their appearance in binaries?
    # -> First instrument instructions that appear in all binaries, then the ones that appear in less binaries
    # in descending order.
    instructions_sorted_by_appearance = sorted(instructions, key=lambda ins: len(ins.occurs_in), reverse=True)

    # Check which combination of instructions can handle which binaries.
    # Answers:
    # - How many binaries could I instrument if the next x instructions (in order) were ready?
    # -> Each combination has x instrumented binaries and y "enabled"/"instrumentable" binaries.
    instrumented = []
    combinations = []
    for instruction in instructions_sorted_by_appearance:
        instrumented.append(instruction)
        instr = copy.copy(instrumented)
        combinations.append(Combination(instr, binaries))

    # Write results to text files.
    results_path = path + "/results"
    with open(f"{results_path}/instructions_per_binary.csv", "w") as file:
        file.write("Binary;Number of distinct mnemonics\n")
        for binary in binaries:
            file.write(f"{binary.filename};{len(binary.mnemonics)}\n")

    with open(f"{results_path}/instructions_sorted_by_appearance.csv", "w") as file:
        file.write("Mnemonic;Appears in x binaries;Binaries\n")
        for instruction in instructions_sorted_by_appearance:
            file.write(f"{instruction.mnemonic};{len(instruction.occurs_in)},{instruction.occurs_in}\n")

    with open(f"{results_path}/covered_binaries_with_given_instructions.csv", "w") as file:
        file.write(
            "Number of instrumented instructions;Number of covered binaries;Binaries;Instrumented instructions\n")
        for combo in combinations:
            file.write(f"{combo.num_instrumented};"
                       f"{combo.num_binaries};"
                       f"{[binary.filename for binary in combo.binaries_ready]};"
                       f"{[ins.mnemonic for ins in combo.instrumented_instructions]}\n")

    # Create plots.

    # Instructions per binary.
    df = pandas.read_csv(f"{results_path}/instructions_per_binary.csv", delimiter=";")
    df["Instructions per binary"] = df["Number of distinct mnemonics"].apply(lambda x: int_to_category(x))

    seaborn.set_theme(style="white", font="cochineal")
    order = ["30-39", "40-49", "50-59", "60-69", "70-79", "80-89", "90-99", "100-109"]
    countplot = seaborn.countplot(data=df, x="Instructions per binary", color="#BDD7EE", order=order)
    seaborn.despine()
    countplot.set_xlabel("Instructions per binary")
    countplot.set_ylabel("Number of binaries")
    fig = countplot.get_figure()
    fig.savefig("ins_per_binary.pdf")
    fig.clear()

    # Combinations.
    seaborn.set_theme(style="ticks", font="cochineal")
    dope = pandas.read_csv(f"{results_path}/covered_binaries_with_given_instructions.csv", delimiter=";")
    lineplot = seaborn.lineplot(data=dope, x="Number of instrumented instructions", y="Number of covered binaries", color="#AAC1D8")
    seaborn.despine()
    plt.xlim(0,170)
    plt.ylim(0,110)
    lineplot.set_xlabel("Instrumented instructions")
    lineplot.set_ylabel("Covered binaries")
    figi = lineplot.get_figure()
    figi.savefig("covered_binaries.pdf")