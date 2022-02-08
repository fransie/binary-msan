#include <iostream>
#include <irdb-elfdep>
#include "jumps.hpp"

using namespace IRDB_SDK;


std::string JumpsPass::getStepName(void) const{
    return "msan";
}

int JumpsPass::parseArgs(const std::vector<std::string> step_args){
    return 0;
}

int JumpsPass::executeStep() {
    FileIR_t *ir = getMainFileIR();
    //registerDependencies();

    // log start
    cout << "Starting jump pass." << endl;
    Eflags::EflagsAccess ea = Eflags::EflagsAccess();

	// get read eflags for conditional branches
	const auto instructions = ir->getInstructions();
    for(auto const &instruction : instructions){
        const auto decodedInstruction = DecodedInstruction_t::factory(instruction);
        if(decodedInstruction->isConditionalBranch()){
            const auto databits = instruction->getDataBits().c_str();
            const auto opcode = reinterpret_cast<const uint8_t*>(databits);
			auto flags = ea.get_read_flag(opcode);
            cout << "Instruction " << instruction->getDisassembly() << ": ";
            insertEFlagsCheckInstrumentation(flags, instruction, ir);
        }
    }
    // success!
	return 0;
}

void JumpsPass::registerDependencies()
{
    auto elfDeps = ElfDependencies_t::factory(getMainFileIR());
    elfDeps->prependLibraryDepedencies("libgcc_s.so.1");
    getMainFileIR()->assembleRegistry();
}

void JumpsPass::insertEFlagsCheckInstrumentation(const std::vector<Eflags::Flag>& flags, Instruction_t* instruction, FileIR_t* fileIR) const{
    // check if flags are poisoned
    for (auto i : flags){
        cout << (int) i << "" ;
        //TODO: probably store shadow as one byte to read it more easily that one bit

        std::string instrumentation = std::string();
        instrumentation.append(
                "pushf\n"        // save eflags
                "push   rax\n"      // save rax
                "mov    al, %%1\n"  // load shadow
                "test   al, al\n"   // test if shadow is zero
                "pop    rax\n"      // restore rax
                "je     0\n"        // skip warning if shadow is zero TODO: verify that this jump here isn't instrumented
//                "call   msan_warning\n"      // TODO: replace with correct function
                "popf\n"            // restore eflags
        );
        const long flag_address {eflagShadowOffset + ((int) i * 8)};
        vector<basic_string<char>> instrumentationParams {to_string(flag_address)};

        const auto new_instr = insertAssemblyInstructionsBefore(fileIR, instruction, instrumentation, instrumentationParams);
        new_instr[5]->setTarget(new_instr[new_instr.size()-1]);
    }
    cout << endl;
}
