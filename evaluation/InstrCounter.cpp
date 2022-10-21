#include "InstrCounter.h"
#include <iostream>
#include <fstream>

InstrCounter::InstrCounter(IRDB_SDK::FileIR_t *fileIR): Transform_t(fileIR) {};

bool InstrCounter::executeStep() {
    std::cout << "Starting executeStep" << std::endl;
    // Find mnemonics used by this file.
    std::set<std::string> mnemonics = {};
    auto functions = getFileIR()->getFunctions();
    for (auto const &function: functions) {
        auto instructions = function->getInstructions();
        for (auto instruction: instructions) {
            auto decodedInstr = IRDB_SDK::DecodedInstruction_t::factory(instruction);
            mnemonics.insert(decodedInstr->getMnemonic());
        }
    }

    // Write results to a CSV.
    std::ofstream MyFile( filename + ".txt");
    std::cout << "Writing to : " << filename << ".txt" << std::endl;
    // Write to the file
    for (const auto& mnemonic : mnemonics){
        MyFile << mnemonic << std::endl;
    }

    // Close the file
    MyFile.close();
    return true;
}