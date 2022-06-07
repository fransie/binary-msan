//
// Created by Franziska Mäckel on 05.06.22.
//

#include "TestHandler.h"

using namespace IRDB_SDK;
using namespace std;

TestHandler::TestHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr) {
    capstone = make_unique<CapstoneService>();
}

const std::vector<std::string> &TestHandler::getAssociatedInstructions() {
    return associatedInstructions;
}

//TODO: consider memory destination operand, not only register. Right now, this function assumes destination to be
// a general purpose register.
void TestHandler::instrument(IRDB_SDK::Instruction_t *instruction) {
    cout << "TestHandler. Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << endl;
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            if(operands[0]->getRegNumber() == operands[1]->getRegNumber()){
                // test regX, regX
                instrumentSingleRegTest(instruction);
            } else {
                // test regX, regY
                instrumentRegRegTest(instruction);
            }
        }
        if (operands[1]->isConstant()){
            // test reg, imm
            instrumentSingleRegTest(instruction);
        }
    } else {
        // dest is memory
    }
}

void TestHandler::instrumentSingleRegTest(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto width = capstone->getDestOperandWidth(instruction);
    string instrumentation = string() +
                             "pushf\n" +           // save eflags (necessary?)
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // first argument
                             "mov rsi, %%2\n" +    // second argument
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation() +
                             "popf\n";             // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    new_instr[12]->setTarget(RuntimeLib::setFlagsAfterTest_Reg);
    cout << "instrumentSingleRegTest: Inserted the following instrumentation: " << instrumentation << endl;
}

void TestHandler::instrumentRegRegTest(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto src = operands[1]->getRegNumber();
    auto width = capstone->getDestOperandWidth(instruction);
    string instrumentation = string() +
                             "pushf\n" +           // save eflags (necessary?)
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // first argument
                             "mov rsi, %%2\n" +    // second argument
                             "mov rdx, %%3\n" +    // second argument
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation() +
                             "popf\n";             // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string((int)src), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    new_instr[13]->setTarget(RuntimeLib::setFlagsAfterTest_RegReg);
    cout << "instrumentRegRegTest: Inserted the following instrumentation: " << instrumentation << endl;
}