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
    directory = path + "/binaries"
    binaries = []
    for filename in [f for f in os.listdir(directory) if isfile(join(directory, f))]:
        binaries.append(Binary(filename, path))
    return binaries


def get_instructions_in_directory(paths, binaries):
    instructions = []
    mnemonics = set(())
    for path in paths:
        with open(f"{path}/results/list_of_instructions_used.txt", 'r') as instructions_file:
            for mnemonic in instructions_file:
                mnemonic = mnemonic.replace("\n", "")
                mnemonics.add(mnemonic)
    for mnemonic in mnemonics:
        instructions.append(Instruction(mnemonic, binaries))
    return instructions


def distinct_instructions_to_category(number):
    if number >= 110:
        return "110-131"
    x = int(number / 10) * 10
    y = x + 9
    return f"{x}-{y}"


def appearances_to_category(number):
    if number == 1:
        return "1"
    elif number == 124:
        return "all 124"
    elif number <= 25:
        return "2-25"
    elif number <= 50:
        return "26-50"
    elif number <= 100:
        return "51-100"
    else:
        return "101-123"


if __name__ == '__main__':
    paths = ["coreutils", "findutils", "binutils"]

    # Answers:
    # - How many distinct instructions does a binary have?  -> binary.distinct_instructions
    # - Which instructions are used in all 129 the coreutils?   -> [ins.mnemonic for ins in instrumented_mnemonics]
    # - In how many binaries does an instruction appear?    -> instruction.occurs_in
    binaries = []
    for path in paths:
        path_binaries = get_binaries_in_directory(path)
        binaries.extend(path_binaries)
    binaries.sort(key=lambda bin: bin.distinct_instructions, reverse=True)
    instructions = get_instructions_in_directory(paths, binaries)

    # Answers:
    # - In which order should the next instructions be instrumented based on their appearance in binaries?
    # -> First instrument instructions that appear in all 129 binaries, then the ones that appear in less binaries
    # in descending order.
    instructions.sort(key=lambda ins: ins.mnemonic)
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
    results_path = "results/"
    with open(f"{results_path}/instructions_per_binary.csv", "w") as file:
        file.write("Binary;Number of distinct mnemonics\n")
        for binary in binaries:
            file.write(f"{binary.filename};{len(binary.mnemonics)}\n")

    with open(f"{results_path}/instructions_sorted_by_appearance.csv", "w") as file:
        file.write("Mnemonic;Appears in x binaries;Binaries\n")
        for instruction in instructions_sorted_by_appearance:
            file.write(f"{instruction.mnemonic};{len(instruction.occurs_in)};{instruction.occurs_in}\n")

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
    df["Instructions per binary"] = df["Number of distinct mnemonics"].apply(
        lambda x: distinct_instructions_to_category(x))

    seaborn.set_theme(style="ticks", font="cochineal", font_scale=1.1)
    order = ["40-49", "50-59", "60-69", "70-79", "80-89", "90-99", "100-109", "110-131"]
    countplot = seaborn.countplot(data=df, x="Instructions per binary", color="#00457D", order=order)
    seaborn.despine()
    countplot.set_xlabel("Distinct mnemonics per binary")
    countplot.set_ylabel("Number of binaries")
    plt.tick_params(bottom=False)
    fig = countplot.get_figure()
    fig.savefig(f"{results_path}/ins_per_binary.pdf")
    fig.clear()

    # Appearances per mnemonic.
    df = pandas.read_csv(f"{results_path}/instructions_sorted_by_appearance.csv", delimiter=";")
    df["Appearance category"] = df["Appears in x binaries"].apply(lambda x: appearances_to_category(x))
    print(df)
    order = ["1", "2-25", "26-50", "51-100", "101-123", "all 124"]
    countplot = seaborn.countplot(data=df, x="Appearance category", color="#00457D", order=order)
    seaborn.despine()
    countplot.set_xlabel("Mnemonic appears in x binaries")
    countplot.set_ylabel("Number of mnemonics")
    plt.tick_params(bottom=False)
    fig = countplot.get_figure()
    fig.savefig(f"{results_path}/appearance_per_ins.pdf")
    fig.clear()

    # Combinations.
    dope = pandas.read_csv(f"{results_path}/covered_binaries_with_given_instructions.csv", delimiter=";")
    lineplot = seaborn.lineplot(data=dope, x="Number of instrumented instructions", y="Number of covered binaries",
                                color="#00457D")
    seaborn.despine()
    plt.xlim(0, 200)
    plt.ylim(0, 124)
    lineplot.set_xlabel("Assumed instrumented mnemonics")
    lineplot.set_ylabel("Covered binaries")
    figi = lineplot.get_figure()
    figi.savefig(f"{results_path}/covered_binaries.pdf")

    print(f"Number of binaries: {len(binaries)}")
    print(f"Number of distinct mnemonics: {len(instructions)}")
