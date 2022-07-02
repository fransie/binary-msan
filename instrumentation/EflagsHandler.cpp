//
// Created by Franziska Mäckel on 01.07.22.
//

#include <irdb-transform>
#include "EflagsHandler.h"
#include "RuntimeLib.h"
#include "Utils.h"

using namespace IRDB_SDK;
using namespace std;

void EflagsHandler::instrument(IRDB_SDK::Instruction_t *instruction) {
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            if(operands[0]->getRegNumber() == operands[1]->getRegNumber()){
                // test regX, regX
                propagateRegShadowToEflags(instruction);
            } else {
                // test regX, regY
                propagateRegOrRegShadowToEflags(instruction);
            }
        } else if (operands[1]->isConstant()){
            // reg and immediate
            propagateRegShadowToEflags(instruction);
        } else if (operands[1]->isMemory()) {
            // reg and mem
            propagateRegOrMemShadowToEflags(instruction);
        }
    } else if (operands[0]->isMemory()) {
        if(operands[1]->isGeneralPurposeRegister()){
            // mem and reg
            propagateRegOrMemShadowToEflags(instruction);
        } else if (operands[1]->isConstant()){
            // mem and immediate
            propagateMemShadowToEflags(instruction);
        }
    }
}

const std::vector<std::string> &EflagsHandler::getAssociatedInstructions() {
    return associatedInstructions;
}

EflagsHandler::EflagsHandler(IRDB_SDK::FileIR_t *fileIr) : fileIr(fileIr){
    capstone = make_unique<CapstoneService>();
}

void EflagsHandler::propagateRegShadowToEflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto width = capstone->getRegWidth(instruction, 0);
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +
                             "mov rsi, %%2\n" +
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    new_instr[12]->setTarget(RuntimeLib::isRegFullyDefined);
    new_instr[14]->setTarget(RuntimeLib::setEflags);
}

void EflagsHandler::propagateMemShadowToEflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = capstone->getMemoryOperandDisassembly(instruction);
    auto destWidth = operands[0]->getArgumentSizeInBytes();
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "lea rdi, %%1\n" +
                             "mov rsi, %%2\n" +
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams {dest, to_string(Utils::toHex(destWidth))};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    new_instr[12]->setTarget(RuntimeLib::isMemFullyDefined);
    new_instr[14]->setTarget(RuntimeLib::setEflags);
}

void EflagsHandler::propagateRegOrRegShadowToEflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    auto src = operands[1]->getRegNumber();
    auto destWidth = capstone->getRegWidth(instruction, 0);
    auto srcWidth = capstone->getRegWidth(instruction, 1);
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // dest
                             "mov rsi, %%2\n" +    // destWidth
                             "mov rdx, %%3\n" +    // src
                             "mov rcx, %%4\n" +    // srcWidth
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string(destWidth), to_string((int)src), to_string(srcWidth)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    new_instr[14]->setTarget(RuntimeLib::isRegOrRegFullyDefined);
    new_instr[16]->setTarget(RuntimeLib::setEflags);
}


void EflagsHandler::propagateRegOrMemShadowToEflags(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    int reg;
    int width;
    if(operands[0]->isGeneralPurposeRegister()){
        reg = operands[0]->getRegNumber();
        width = capstone->getRegWidth(instruction, 0);
    } else{
        reg = operands[1]->getRegNumber();
        width = capstone->getRegWidth(instruction, 1);
    }
    auto memory = capstone->getMemoryOperandDisassembly(instruction);
    string instrumentation = string() +
                             Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // reg
                             "lea rsi, %%2\n" +    // mem
                             "mov rdx, %%3\n" +    // width
                             "call 0\n" +
                             "mov dil, al\n" +
                             "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation();
    vector<basic_string<char>> instrumentationParams {to_string(reg), memory, to_string(width)};
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    new_instr[13]->setTarget(RuntimeLib::isRegOrMemFullyDefined);
    new_instr[15]->setTarget(RuntimeLib::setEflags);
}

