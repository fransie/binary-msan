#include <iostream>
#include <irdb-elfdep>
#include <irdb-cfg>
#include "jumps.hpp"
#include "eflags_access.hpp"

using namespace IRDB_SDK;


std::string JumpsPass::getStepName(void) const{
    return "jumps_pass";
}

int JumpsPass::parseArgs(const std::vector<std::string> step_args){
    return 0;
}

int JumpsPass::executeStep() {
    FileIR_t *ir = getMainFileIR();

    // log start
    cout << "Starting jump pass." << endl;
    Eflags::EflagsAccess ea = Eflags::EflagsAccess();

	// get read eflags for conditional branches
	const auto instructions = ir->getInstructions();
    for(auto const &instruction : instructions){
        const auto decodedInstruction = DecodedInstruction_t::factory(instruction);        
        if(decodedInstruction->isConditionalBranch()){
			const auto databits = instruction->getDataBits().c_str();
            const uint8_t* opcode = reinterpret_cast<const uint8_t*>(databits);
			auto flags = ea.get_read_flag(opcode);

            cout << "Instruction " << instruction->getDisassembly() << " has flags: ";
            for (auto i : flags){
               cout << (int) i << " ";   
            }
            cout << endl;
            // check if flags are poisoned
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
