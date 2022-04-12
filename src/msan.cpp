//
// Created by Franziska Mäckel on 03.04.22.
//

#include "msan.hpp"
#include <irdb-elfdep>
#include "interface.h"

using namespace IRDB_SDK;
using namespace std;


namespace Registers{
    enum class Register {
        RAX = 0,
        RCX = 1,
        RDX = 2,
        RBX = 3,
        RSP = 4,
        RBP = 5,
        RSI = 6,
        RDI = 7,
        R8 = 8,
        R9 = 9,
        R10 = 10,
        R11 = 11,
        R12 = 12,
        R13 = 13,
        R14 = 14,
        R15 = 15
    };
}


// constructor
MSan::MSan(FileIR_t *p_variantIR)
        :
        Transform_t(p_variantIR) // init Transform_t class for insertAssembly and getFileIR
{
    registerDependencies();
    setUpCapstone();
}

MSan::~MSan() {
    cs_close(&capstoneHandle);
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
// TODO: handle immediate values, segment registers and memory locations as operands
/**
 * Takes a mov instruction and inserts instrumentation before it so that the shadow is handled correctly.
 */
void MSan::moveHandler(Instruction_t *instruction){
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            instrumentRegToRegMove(instruction);
        }
        if (operands[1]->isConstant()){
            instrumentImmediateToRegMove(instruction);
        }
        else {
            // mem to reg
        }
    } else {
        // reg to mem
    }
}

void MSan::instrumentImmediateToRegMove(Instruction_t *instruction) {// immediate to reg
    auto operands = DecodedInstruction_t::factory(instruction)->getOperands();
    auto dest = static_cast<Registers::Register>(operands[0]->getRegNumber());
    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and immediate: " << operands[1]->getConstant() << endl;

    auto width = operands[0]->getArgumentSizeInBits();
    if(isHigherByteRegister(getCapstoneRegister(instruction))){
        width = HIGHER_BYTE;
    }
    // Value is interpreted as hex in binary (due to zipr? idk), therefore convert to hex value.
    std::stringstream width_decimal;
    width_decimal << std::hex << width;

    string instrumentation = string() +
                             "pushf\n" +           // save eflags (necessary?)
                             getPushCallerSavedRegistersInstrumentation() +
                             "mov rdi, %%1\n" +    // first argument
                             "mov rsi, %%2\n" +    // second argument
                             "call 0\n" +
                             getPopCallerSavedRegistersInstrumentation() +
                             "popf\n";             // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), width_decimal.str()};
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
    const auto dest = static_cast<Registers::Register>(operands[0]->getRegNumber());
    const auto source = static_cast<Registers::Register>(operands[1]->getRegNumber());


    auto width = operands[0]->getArgumentSizeInBits();
    if(isHigherByteRegister(getCapstoneRegister(instruction))){
        width = HIGHER_BYTE;
    }
    // Value is interpreted as hex in binary (due to zipr? idk), therefore convert to hex value.
    std::stringstream width_decimal;
    width_decimal << std::hex << width;

    cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and source: " << (int) source << endl;

    // place reg numbers in argument registers according to calling conventions and add call to runtime library
    std::string instrumentation = std::string() +
                                  "pushf\n" +           // save eflags (necessary?)
                                  this->getPushCallerSavedRegistersInstrumentation() +
                                  "mov rdi, %%1\n" +    // first argument
                                  "mov rsi, %%2\n" +    // second argument
                                  "mov rdx, %%3\n"      // third argument
                                  "call 0\n" +
                                  this->getPopCallerSavedRegistersInstrumentation() +
                                  "popf\n";             // restore eflags
    vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string((int)source), width_decimal.str()};
    const auto new_instr = ::insertAssemblyInstructionsBefore(this->getFileIR(), instruction, instrumentation, instrumentationParams);

    // set target of "call 0"
    new_instr[13]->setTarget(regToRegShadowCopy);
    cout << "Inserted the following instrumentation: " << instrumentation << endl;
}


/**
 * Takes an assembly add-instruction and inserts instrumentation before the instruction which
 * handles the shadow propagation.
 * @param instruction the add instruction to be instrumented
 */
void MSan::addHandler(Instruction_t *instruction){

}


/**
 * Returns a string containing pushes to all caller-saved general purpose registers, namely
 *  RAX, RCX, RDX, RSI, RDI, R8, R9, R10 , R11.
 *  Number of instructions: 9.
 * @return string of assembly push instructions
 */
string MSan::getPushCallerSavedRegistersInstrumentation(){
    return std::string() +
    "push   rax\n" +
            "push   rcx\n" +
            "push   rdx\n" +
            "push   rsi\n" +
            "push   rdi\n" +
            "push   r8w\n" +
            "push   r9w\n" +
            "push   r10w\n" +
            "push   r11w\n";
}

/**
 * Returns a string containing pops into all general purpose registers, namely
 *  RAX, RCX, RDX, RSI, RDI, R8, R9, R10 , R11 to restore caller-saved registers.
 *  Number of instructions: 9.
 * @return string of assembly pop instructions
 */
string MSan::getPopCallerSavedRegistersInstrumentation(){
    return std::string() +
            "pop   r11w\n" +
            "pop   r10w\n" +
            "pop   r9w\n" +
            "pop   r8w\n" +
            "pop   rdi\n" +
            "pop   rsi\n" +
            "pop   rdx\n" +
            "pop   rcx\n" +
            "pop   rax\n";
}

void MSan::registerDependencies(){
    auto elfDeps = ElfDependencies_t::factory(getFileIR());
    // TODO: fix absolute paths
    elfDeps->prependLibraryDepedencies("/home/franzi/Documents/binary-msan2/plugins_install/libinterface.so");
    // Msan libraries don't work yet, uncomment if ready
    //elfDeps->prependLibraryDepedencies("/home/franzi/Documents/binary-msan2/sharedlibrary/libmsan_c.so");
    //elfDeps->prependLibraryDepedencies("/home/franzi/Documents/binary-msan2/sharedlibrary/libmsan_cxx.so");
    regToRegShadowCopy = elfDeps->appendPltEntry("_Z18regToRegShadowCopyiii");
    defineRegShadow = elfDeps->appendPltEntry("_Z15defineRegShadowii");
    getFileIR()->assembleRegistry();
}

bool MSan::parseArgs(std::vector<std::string> step_args) {
    return true;
}

void MSan::setUpCapstone() {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstoneHandle) != CS_ERR_OK){
        //TODO: error handling
    }
    cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

// TODO next step: fix seg fault in msan.log -> maybe because instruction->getDataBits destroys the object?
x86_reg MSan::getCapstoneRegister(IRDB_SDK::Instruction_t *instruction) {
    const auto dataBits = instruction->getDataBits();
    const auto opcode = reinterpret_cast<const uint8_t*>(dataBits.c_str());
    cs_insn *capstoneInstruction;
    size_t count = cs_disasm(capstoneHandle, opcode, sizeof(opcode)-1, 0x1000, 0, &capstoneInstruction);
    if (count == 0){
        //TODO: error handling of cs_disasm
        std::cout << "ERROR in getCapstoneRegister";
    }
    auto x86Register = capstoneInstruction->detail->x86.operands[0].reg;
    cs_free(capstoneInstruction, count);
    return x86Register;
}

bool MSan::isHigherByteRegister(x86_reg capstoneRegNumber) {
    switch(capstoneRegNumber){
        case X86_REG_AH:
        case X86_REG_CH:
        case X86_REG_BH:
        case X86_REG_DH:
            return true;
        default:
            return false;
    }
}