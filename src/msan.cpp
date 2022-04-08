//
// Created by Franziska Mäckel on 03.04.22.
//

#include "msan.hpp"
#include <irdb-elfdep>

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
    // Reserves memory for the shadowing of the 16 general purpose registers and initialises.
    // Upon initialisation, all register shadows are undefined (0 = undefined).
    shadowRegisters = std::vector<uint64_t>(16,0);
    regToRegMoveFunction = nullptr;
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
    }
    return true; //success
}

/**
 * Takes a mov instruction and inserts instrumentation before it so that the shadow is handled correctly.
 */
void MSan::moveHandler(Instruction_t *instruction){
    auto decodedInstruction = DecodedInstruction_t::factory(instruction);
    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
    if(operands[0]->isGeneralPurposeRegister()){
        if(operands[1]->isGeneralPurposeRegister()){
            // reg to reg
            auto dest = static_cast<Registers::Register>(operands[0]->getRegNumber());
            auto source = static_cast<Registers::Register>(operands[1]->getRegNumber());
            cout << "Instruction: " << instruction->getDisassembly() << " at " << instruction->getAddress()->getVirtualOffset() << ". Destination register: " << (int) dest << " and source: " << (int) source << endl;

            // place them in argument registers according to calling conventions
            // add call to reg_to_reg_mov

            std::string instrumentation = std::string() +
                              "pushf\n" +           // save eflags (necessary?)
                              getPushCallerSavedRegistersInstrumentation() +
                              "mov rdi, %%1\n" +    // first argument
                              "mov rsi, %%2\n" +    // second argument
                              "call 0\n" +
                              getPopCallerSavedRegistersInstrumentation() +
                              "popf\n";             // restore eflags
            vector<basic_string<char>> instrumentationParams {to_string((int)dest), to_string((int)source)};
            const auto new_instr = ::insertAssemblyInstructionsBefore(getFileIR(), instruction, instrumentation, instrumentationParams);
            // set target of "call 0"
            new_instr[12]->setTarget(regToRegMoveFunction);
            cout << "Inserted the following instrumentation: " << instrumentation << endl;
        }
        else {
            // mem to reg
        }
    } else {
        // reg to mem
    }
}


/**
 * Takes two ints representing registers from Registers.cpp and propagates the shadow value of the
 * source register to the destination register.
 */
void MSan::regToRegMove(const int dest, const int source){
    shadowRegisters[dest] = shadowRegisters[source];
    cout << "This is a test." << endl;
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
    elfDeps->prependLibraryDepedencies("/home/franzi/Documents/binary-msan2/plugins_install/libinterface.so");
    regToRegMoveFunction = elfDeps->appendPltEntry("testing");
    getFileIR()->assembleRegistry();
}

bool MSan::parseArgs(std::vector<std::string> step_args) {
    return true;
}
