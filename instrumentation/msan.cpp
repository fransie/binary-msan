//
// Created by Franziska Mäckel on 03.04.22.
//

#include "msan.hpp"
#include <irdb-elfdep>
#include <memory>
#include "utils.h"

using namespace IRDB_SDK;
using namespace std;

// constructor
MSan::MSan(FileIR_t *fileIR)
        :
        Transform_t(fileIR) // init Transform_t class for insertAssembly and getFileIR
{
    registerDependencies();
    capstoneService = std::make_unique<CapstoneService>();
}

bool MSan::executeStep()
{
    cout << "Starting msan step." << endl;
    registerDependencies();
    // get main function (for starters)
    Function_t* mainFunction = nullptr;
    auto functions = getFileIR()->getFunctions();
    for (auto const &function : functions){
        if(function->getName() == "main"){
            mainFunction = function;
            break;
        }
    }
    if(!mainFunction){
        cout << "No main function detected." << endl;
    }

    // loop over instructions and add handlers to common functions
    auto instructions = mainFunction->getInstructions();
    for (auto instruction : instructions){
        auto decodedInstruction = DecodedInstruction_t::factory(instruction);
        auto decodedInstructionCopy = DecodedInstruction_t::factory(instruction);
        auto mnemonic = decodedInstruction->getMnemonic();
        if(mnemonic == "mov"){
            moveHandler(instruction);
        }
        if(mnemonic == "add"){
            addHandler(instruction);
        }
    }
    return true; //success
}

// TODO: handle operand sizes other than 64 bit
// TODO: handle segment registers and memory locations as operands
/**
 * Takes a mov instruction and inserts instrumentation before it so that the shadow is handled correctly.
 */
void MSan::moveHandler(Instruction_t *instruction){
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            // reg to reg
            instrumentRegToRegMove(instruction);
        }
        if (operands[1]->isConstant()){
            // immediate to reg
            instrumentImmediateToRegMove(instruction);
        }
        if (operands[1]->isMemory()) {
            // memory to reg
            instrumentMemToRegMove(instruction);
        }
    } else {
        // reg to mem
    }
}

void MSan::instrumentImmediateToRegMove(Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and immediate: " << operands[1]->getConstant() << endl;


    auto width = capstoneService->getOperandWidth(instruction);
    string instrumentation = string() +
                             "pushf\n" +           // save eflags (necessary?)
                             utils::getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // first argument
                             "mov rsi, %%2\n" +    // second argument
                             "call 0\n" +
                             utils::getPopCallerSavedRegistersInstrumentation() +
                             "popf\n";             // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string(width)};
    const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(getFileIR(), instruction, instrumentation, instrumentationParams);

    // set target of "call 0"
    new_instr[12]->setTarget(defineRegShadow);
    cout << "Inserted the following instrumentation: " << instrumentation << endl;
}

/**
 * Takes a move instruction from one general purpose registers to another and inserts shadow propagating
 * instrumentation before the instruction.
 * @param instruction a pointer to the move instruction
 */
void MSan::instrumentRegToRegMove(IRDB_SDK::Instruction_t *instruction) {
    const auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    const auto dest = operands[0]->getRegNumber();
    const auto source = operands[1]->getRegNumber();
    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << dest << " and source: " << source << endl;

    auto width = capstoneService->getOperandWidth(instruction);
    std::string instrumentation = std::string() +
                                  "pushf\n" +           // save eflags (necessary?)
                                  utils::getPushCallerSavedRegistersInstrumentation() +
                                  "mov rdi, %%1\n" +    // first argument
                                  "mov rsi, %%2\n" +    // second argument
                                  "mov rdx, %%3\n"      // third argument
                                  "call 0\n" +
                                  utils::getPopCallerSavedRegistersInstrumentation() +
                                  "popf\n";             // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string(dest), to_string(source), to_string(width)};
    const auto new_instr = ::insertAssemblyInstructionsBefore(this->getFileIR(), instruction, instrumentation, instrumentationParams);

    // set target of "call 0"
    new_instr[13]->setTarget(regToRegShadowCopy);
    cout << "Inserted the following instrumentation: " << instrumentation << endl;
}


void MSan::instrumentMemToRegMove(IRDB_SDK::Instruction_t *instruction) {
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = operands[0]->getRegNumber();
    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and mem: " << operands[1]->getString() << endl;

    instrumentMemRef(operands[1], instruction);
}

void MSan::instrumentMemRef(const shared_ptr<DecodedOperand_t> &operand, IRDB_SDK::Instruction_t *instruction) {
    if(operand->hasBaseRegister()){
        auto baseReg = operand->getBaseRegister();
        auto baseRegWidth = capstoneService->getBaseRegWidth(instruction);

        string instrumentation = string() +
                                 "pushf\n" +           // save eflags (necessary?)
                                 utils::getPushCallerSavedRegistersInstrumentation() +
                                 "mov rdi, %%1\n" +    // first argument
                                 "mov rsi, %%2\n" +    // second argument
                                 "call 0\n" +
                                 utils::getPopCallerSavedRegistersInstrumentation() +
                                 "popf\n";             // restore eflags
        vector<basic_string<char>> instrumentationParams {to_string(baseReg), to_string(baseRegWidth)};
        const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(getFileIR(), instruction, instrumentation, instrumentationParams);
        new_instr[12]->setTarget(checkRegIsInit);
        cout << "Inserted the following instrumentation: " << instrumentation << endl;
    }
    if(operand->hasIndexRegister()){
        auto indexReg = operand->getIndexRegister();
        auto indexRegWidth = capstoneService->getIndexRegWidth(instruction);

        string instrumentation = string() +
                                 "pushf\n" +           // save eflags (necessary?)
                                 utils::getPushCallerSavedRegistersInstrumentation() +
                                 "mov rdi, %%1\n" +    // first argument
                                 "mov rsi, %%2\n" +    // second argument
                                 "call 0\n" +
                                 utils::getPopCallerSavedRegistersInstrumentation() +
                                 "popf\n";             // restore eflags
        vector<basic_string<char>> instrumentationParams {to_string(indexReg), to_string(indexRegWidth)};
        const auto new_instr = ::IRDB_SDK::insertAssemblyInstructionsBefore(getFileIR(), instruction, instrumentation, instrumentationParams);
        new_instr[12]->setTarget(checkRegIsInit);
        cout << "Inserted the following instrumentation: " << instrumentation << endl;
    }

}

/**
 * Takes an assembly add-instruction and inserts instrumentation before the instruction which
 * handles the shadow propagation.
 * @param instruction the add instruction to be instrumented
 */
void MSan::addHandler(Instruction_t *instruction){

}

void MSan::registerDependencies(){
    auto elfDeps = ElfDependencies_t::factory(getFileIR());
    // TODO: fix absolute paths

    const string runtimeLibPath = "/home/franzi/Documents/binary-msan/plugins_install/";
    elfDeps->prependLibraryDepedencies(runtimeLibPath + "libinterface.so");
    regToRegShadowCopy = elfDeps->appendPltEntry("_Z18regToRegShadowCopyiii");
    defineRegShadow = elfDeps->appendPltEntry("_Z15defineRegShadowii");
    checkRegIsInit = elfDeps->appendPltEntry("_Z14checkRegIsInitii");

    const string compilerRtPath = "/home/franzi/Documents/llvm-project-llvmorg-13.0.1/buildcompilerRT/lib/linux/";
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan_cxx-x86_64.so");
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan-x86_64.so");


    getFileIR()->assembleRegistry();
}

bool MSan::parseArgs(std::vector<std::string> step_args) {
    return true;
}