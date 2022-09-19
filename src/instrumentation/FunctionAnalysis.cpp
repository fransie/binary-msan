#include "FunctionAnalysis.h"


FunctionAnalysis::FunctionAnalysis(IRDB_SDK::Function_t *function) {
    this->function = function;
    analyse();
}

/**
 * Checks whether the input function is a leaf function or uses a tail call by
 * looking for a <code>call</code> instruction.
 * @param function input function.
 */
void FunctionAnalysis::analyse() {
    auto instructions = function->getInstructions();
    for (auto instruction: instructions) {
        auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
        if (decodedInstruction->getMnemonic() == "call") {
            this->isLeafOrTailCallFunction = false;
            return;
        }
    }
    this->isLeafOrTailCallFunction = true;
}

IRDB_SDK::Function_t *FunctionAnalysis::getFunction() const {
    return function;
}
