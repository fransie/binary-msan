import os
from os.path import isfile, join

from typing import List


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
        combinations.append(Combination(instrumented, binaries))