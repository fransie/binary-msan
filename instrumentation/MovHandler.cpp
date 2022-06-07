//
// Created by Franziska Mäckel on 04.06.22.
//

#include "MovHandler.h"

using namespace IRDB_SDK;
using namespace std;


// TODO: handle operand sizes other than 64 bit
// TODO: handle segment registers as operands
/**
 * Takes a mov instruction and inserts instrumentation before it so that the shadow is handled correctly.
 */
void MovHandler::instrument(Instruction_t *instruction){
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            // reg to reg
            instrumentRegToRegMove(instruction);
        }
        if (operands[1]->isConstant()){
            // immediate to reg
            instrumentImmToRegMove(instruction);
        }
        if (operands[1]->isMemory()) {
            // memory to reg
            instrumentMemToRegMove(instruction);
        }
    } else {
        // reg to mem
    }
}

void MovHandler::instrumentImmToRegMove(Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and immediate: " << operands[1]->getConstant() << endl;


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
    new_instr[12]->setTarget(RuntimeLib::defineRegShadow);
    cout << "Inserted the following instrumentation: " << instrumentation << endl;
}

/**
 * Takes a move instruction from one general purpose registers to another and inserts shadow propagating
 * instrumentation before the instruction.
 * @param instruction a pointer to the move instruction
 */
void MovHandler::instrumentRegToRegMove(Instruction_t *instruction) {
    const auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    const auto dest = operands[0]->getRegNumber();
    const auto source = operands[1]->getRegNumber();
    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << dest << " and source: " << source << endl;

    auto width = capstone->getDestOperandWidth(instruction);
    string instrumentation = string() +
                             "pushf\n" +           // save eflags (necessary?)
                                  Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // first argument
                                  "mov rsi, %%2\n" +    // second argument
                                  "mov rdx, %%3\n"      // third argument
                                  "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation() +
                             "popf\n";             // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string(dest), to_string(source), to_string(width)};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    new_instr[13]->setTarget(RuntimeLib::regToRegShadowCopy);
    cout << "Inserted the following instrumentation: " << instrumentation << endl;
}

void MovHandler::instrumentMemToRegMove(Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    cout << "instrumentMemToRegMove. Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and mem: " << operands[1]->getString() << endl;

    instruction = MemoryAccessHandler::instrumentMemRef(operands[1], instruction, capstone, fileIr);
    auto memoryDisassembly = getMemoryOperandDisassembly(instruction);
    auto width = capstone->getDestOperandWidth(instruction);
    string instrumentation = string() +
                             "pushf\n" +           // save eflags (necessary?)
                                  Utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // reg
                                  "mov rsi, %%2\n" +    // regWidth
                                  "lea rdx, %%3\n" +    // memAddr
                                  "call 0\n" +
                             Utils::getPopCallerSavedRegistersInstrumentation() +
                             "popf\n";             // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string(dest), to_string(width), memoryDisassembly};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(fileIr, instruction, instrumentation, instrumentationParams);
    new_instr[13]->setTarget(RuntimeLib::memToRegShadowCopy);
    cout << "Inserted the following instrumentation: " << instrumentation << endl;
}

string MovHandler::getMemoryOperandDisassembly(Instruction_t *instruction) {
    auto disassembly = instruction->getDisassembly();
    auto openBracketPosition = disassembly.find_first_of('[');
    if(openBracketPosition == string::npos){
        cerr << "movHandler: Instruction " << instruction->getDisassembly() << " does not include a memory operand. Abort." << endl;
        throw invalid_argument("movHandler: Instruction " + instruction->getDisassembly() + " does not include a memory operand. Abort.");
    }
    auto closingBracketPosition = disassembly.find_first_of(']');
    auto len = closingBracketPosition - openBracketPosition;
    auto substring = disassembly.substr(openBracketPosition, len + 1);
    return substring;
}

MovHandler::MovHandler(FileIR_t *fileIr) : fileIr(fileIr){
    capstone = make_unique<CapstoneService>();
}

std::string &MovHandler::getAssociatedInstruction() {
    return associatedInstruction;
}
