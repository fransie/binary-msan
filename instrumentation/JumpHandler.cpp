//
// Created by Franziska Mäckel on 07.06.22.
//

#include "JumpHandler.h"

using namespace IRDB_SDK;
using namespace std;

JumpHandler::JumpHandler(FileIR_t *fileIr) : fileIr(fileIr) {

}

const std::vector<std::string> &JumpHandler::getAssociatedInstructions() {
    return associatedInstructions;
}

//TODO: check out all jumps that can be handled like this
void JumpHandler::instrument(Instruction_t *instruction) {
    cout << "JumpHandler. Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << endl;
    string instrumentation = string() +
                             "pushf\n" +           // save eflags (necessary?)
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation() +
                             "popf\n";             // restore eflags
    const auto new_instr = insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation,{});
    new_instr[10]->setTarget(RuntimeLib::checkEflags);
    cout << "Inserted the following instrumentation: " << instrumentation << endl;
}

