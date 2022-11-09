#include <irdb-elfdep>
#include <unistd.h>
#include "RuntimeLib.h"
#include "Utils.h"
#include "EflagsHandler.h"
#include "FunctionAnalysis.h"
#include "MSan.h"
#include "LeaHandler.h"
#include "ControlFlowHandler.h"
#include "BinaryArithmeticHandler.h"
#include "BinaryLogicHandler.h"
#include "MemoryAccessHandler.h"
#include "MovHandler.h"
#include "StackVariableHandler.h"
#include <algorithm>

using namespace IRDB_SDK;
using namespace std;

MSan::MSan(FileIR_t *fileIR) : Transform_t(fileIR) {
    functionHandlers.push_back(make_unique<StackVariableHandler>(fileIR));
    instructionHandlers.push_back(make_unique<MemoryAccessHandler>(fileIR));
    instructionHandlers.push_back(make_unique<MovHandler>(fileIR));
    instructionHandlers.push_back(make_unique<EflagsHandler>(fileIR));
    instructionHandlers.push_back(make_unique<ControlFlowHandler>(fileIR));
    instructionHandlers.push_back(make_unique<BinaryArithmeticHandler>(fileIR));
    instructionHandlers.push_back(make_unique<BinaryLogicHandler>(fileIR));
    instructionHandlers.push_back(make_unique<LeaHandler>(fileIR));
}

bool MSan::executeStep() {
    registerDependencies();
    Function_t *mainFunction = nullptr;
    Function_t *startFunction = nullptr;
    
    auto functions = getFileIR()->getFunctions();

    //list of functions, that will not be processed/instrumented
    const std::vector<std::string> noInstrumentFunctions = {"_init", "_start", "__libc_csu_init", "__tsan_default_options", "_fini", "__libc_csu_fini",
                                                            "ThisIsNotAFunction", "__gmon_start__", "__do_global_ctors_aux", "__do_global_dtors_aux"};

    for (auto const &function: functions) {
        //cout << "All functions: " << function->getName() << "\n";
        auto functionName = function->getName();
        
        if (functionName == "main") {
            mainFunction = function;
        }

        if (functionName == "_start") {
            startFunction = function;
        }

        //skip functions, that should not be instrumented
        const bool ignoreFunction = std::find(noInstrumentFunctions.begin(), noInstrumentFunctions.end(), functionName) != noInstrumentFunctions.end();
        if (ignoreFunction) {
            cout << "Skipped functions: " << function->getName() << "\n";
            continue;
        }

        if (functionName.find("@plt") != std::string::npos) {
            cout << "Skipped functions: " << function->getName() << "\n";
            continue;
        }
        
        // do not instrument push jump thunks
        if (function->getInstructions().size() == 2 && function->getEntryPoint()->getDisassembly().rfind("push", 0) == 0 &&
                function->getEntryPoint()->getFallthrough()->getDisassembly().rfind("jmp", 0) == 0) {
            cout << "Skipped functions: " << function->getName() << "\n";
            continue;
        }
        
        Function_t *currFunction = function;
        unique_ptr<FunctionAnalysis> currFunctionAnalysis = make_unique<FunctionAnalysis>(currFunction);

        cout << "Instrumented functions: " << function->getName() << "\n";
        functionHandlers.at(0)->instrument(currFunctionAnalysis);
        
        //instrument instructions
        const set<Instruction_t *> originalInstructions(currFunction->getInstructions().begin(),
                                                    currFunction->getInstructions().end());
        for (auto instruction: originalInstructions) {
            for (auto &&handler: instructionHandlers) {
                if (handler->isResponsibleFor(instruction)) {
                    instruction = handler->instrument(instruction);
                }
            }
        }
        
    }
    if (!mainFunction) {
        cout << "No main function detected." << endl;
        //try to identify main function via mov rdi, [mainaddr] in _start 
        if(startFunction) {
            bool foundMainAddr = false;
            std::string mainFuncAddr;

            const set<Instruction_t *> originalInstructions(startFunction->getInstructions().begin(),
                                                    startFunction->getInstructions().end());
            //go through instructions and detect what rdi is set to
            //TODO: verify that it is the correct change of rdi (in front of the call)
            for (auto instruction: originalInstructions) {

                auto decodedInstruction = IRDB_SDK::DecodedInstruction_t::factory(instruction);
                auto mnemonic = decodedInstruction->getMnemonic();


                if(mnemonic == "mov") {
                    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();

                    if(operands[0]->isGeneralPurposeRegister() && operands[1]->isConstant()) {
                        auto reg = operands[0]->getRegNumber();
                        if(reg == 7) {
                            mainFuncAddr = Utils::toHex(operands[1]->getConstant());
                            foundMainAddr = true;
                        }
                    }
                }
                else if(mnemonic == "lea") {
                    vector<shared_ptr<DecodedOperand_t>> operands = decodedInstruction->getOperands();
                    if(operands[0]->isGeneralPurposeRegister() && operands[1]->isMemory()) {
                        auto reg = operands[0]->getRegNumber();
                        if(reg == 7) {

                            mainFuncAddr = operands[1]->getString();
                            foundMainAddr = true;
                        }
                    }
                }
            }
            //main address found, now lookup function with this offset and set this function as mainFunction
            if(foundMainAddr) {
                for (auto const &possibleFunction : functions)
                {
                    auto functionName = possibleFunction->getName();

                    const bool ignoreFunction = std::find(noInstrumentFunctions.begin(), noInstrumentFunctions.end(), functionName) != noInstrumentFunctions.end();
                    if (ignoreFunction)
                    {
                        continue;
                    }

                    if (functionName.find("@plt") != std::string::npos)
                    {
                        continue;
                    }

                    auto offsetAddr = Utils::toHex(possibleFunction->getEntryPoint()->getAddress()->getVirtualOffset());
                    if (offsetAddr == mainFuncAddr)
                    {
                        cout << "main detected via call in _start" << endl;
                        cout << "main offset: " << offsetAddr << endl;
                        mainFunction = possibleFunction;
                        break;
                    }
                }
            }
            
        }
    }

    if(mainFunction) {
        //instrument main Function
        instrumentOptions(mainFunction->getEntryPoint());
    }

    return true; //success
}


void MSan::registerDependencies() {
    auto elfDeps = ElfDependencies_t::factory(getFileIR());

    auto binmsanHome = std::getenv("BINMSAN_HOME");
    if(!binmsanHome){
        throw logic_error("Env variable BINMSAN_HOME is missing!");
    }
    auto binmsanHomeString = std::string(binmsanHome);
    auto runtimeLibPath = binmsanHomeString + "/plugins_install/";
    elfDeps->prependLibraryDepedencies(runtimeLibPath + "libbinmsan_lib.so");

    const string compilerRtPath =  binmsanHomeString + "/llvm_shared_msan_lib/";
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan_cxx-x86_64.so");
    elfDeps->prependLibraryDepedencies(compilerRtPath + "libclang_rt.msan-x86_64.so");

    RuntimeLib::regToRegShadowCopy = elfDeps->appendPltEntry("regToRegShadowCopy");
    RuntimeLib::checkRegIsInit = elfDeps->appendPltEntry("checkRegIsInit");
    RuntimeLib::memToRegShadowCopy = elfDeps->appendPltEntry("memToRegShadowCopy");
    RuntimeLib::checkEflags = elfDeps->appendPltEntry("checkEflags");
    RuntimeLib::initGpRegisters = elfDeps->appendPltEntry("initGpRegisters");
    RuntimeLib::enableLogging = elfDeps->appendPltEntry("enableLogging");
    RuntimeLib::regToMemShadowCopy = elfDeps->appendPltEntry("regToMemShadowCopy");
    RuntimeLib::isRegFullyDefined = elfDeps->appendPltEntry("isRegFullyDefined");
    RuntimeLib::isMemFullyDefined = elfDeps->appendPltEntry("isMemFullyDefined");
    RuntimeLib::isRegOrRegFullyDefined = elfDeps->appendPltEntry("isRegOrRegFullyDefined");
    RuntimeLib::isRegOrMemFullyDefined = elfDeps->appendPltEntry("isRegOrMemFullyDefined");
    RuntimeLib::setRflags = elfDeps->appendPltEntry("setRflags");
    RuntimeLib::setRegShadow = elfDeps->appendPltEntry("setRegShadow");
    RuntimeLib::setMemShadow = elfDeps->appendPltEntry("setMemShadow");
    RuntimeLib::unpoisonUpper4Bytes = elfDeps->appendPltEntry("unpoisonUpper4Bytes");
    RuntimeLib::propagateRegOrRegShadow = elfDeps->appendPltEntry("propagateRegOrRegShadow");
    RuntimeLib::propagateRegOrMemShadow = elfDeps->appendPltEntry("propagateRegOrMemShadow");
    RuntimeLib::propagateMemOrRegShadow = elfDeps->appendPltEntry("propagateMemOrRegShadow");

    RuntimeLib::msan_check_mem_is_initialized = elfDeps->appendPltEntry("__msan_check_mem_is_initialized");
    RuntimeLib::msan_poison_stack = elfDeps->appendPltEntry("__msan_poison_stack");
    RuntimeLib::msan_set_keep_going = elfDeps->appendPltEntry("__msan_set_keep_going");
    RuntimeLib::msan_unpoison = elfDeps->appendPltEntry("__msan_unpoison");

    getFileIR()->assembleRegistry();
}

[[maybe_unused]] bool MSan::parseArgs(std::vector<std::string> step_args) {
    return true;
}

// https://www.gnu.org/savannah-checkouts/gnu/libc/manual/html_node/Example-of-Getopt.html
bool MSan::parseArgs(int argc, char **argv) {
    int c;
    opterr = 0;
    while ((c = getopt(argc, argv, "kl")) != -1) {
        switch (c) {
            case 'k':
                keep_going = true;
                std::cout << "Msan will keep going after warnings." << std::endl;
                break;
            case 'l':
                logging = true;
                std::cout << "Logging enabled." << std::endl;
                break;
            case '?':
                if (optopt == 'c')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                return true;
            default:
                std::cerr << "Error parsing arguments." << std::endl;
                return false;
        }
    }
    return true;
}

void MSan::instrumentOptions(IRDB_SDK::Instruction_t *instruction) {
    // Call to initGpRegisters: Assume RBP and RSP registers are initialised upon entry of main function
    string instrumentation = Utils::getStateSavingInstrumentation() + "call 0\n";
    std::vector<Instruction_t *> targets = {RuntimeLib::initGpRegisters};

    if (keep_going) {
        instrumentation = instrumentation + "mov rdi, 1\ncall 0\n";
        targets.push_back(RuntimeLib::msan_set_keep_going);
    }

    if (logging) {
        instrumentation = instrumentation + "call 0\n";
        targets.push_back(RuntimeLib::enableLogging);
    }

    instrumentation = instrumentation + Utils::getStateRestoringInstrumentation();
    const auto new_instr = IRDB_SDK::insertAssemblyInstructionsAfter(getFileIR(), instruction, instrumentation, {});
    auto calls = DisassemblyService::getCallInstructionPosition(new_instr);
    for (size_t x = 0; x < calls.size(); x++) {
        new_instr[calls[x]]->setTarget(targets[x]);
    }
}