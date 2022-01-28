/*
   Copyright 2017-2019 University of Virginia

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <iostream>
#include <capstone.h>
#include <x86.h>
#include "jumps.hpp"

using namespace IRDB_SDK;
using namespace std;

static const char *get_eflag_name(uint64_t flag);

// constructor
JumpsPass::JumpsPass(FileIR_t *p_variantIR) : Transform_t(p_variantIR)
{
}

bool JumpsPass::execute() {
    // log start
    cout << "Starting jump pass." << endl;

    // create capstone handle

    csh handle;
    cs_insn *insn;
    size_t count;
    cs_regs regs_read, regs_write;
    uint8_t read_count, write_count, i;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
        return false;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    const auto instructions = getFileIR()->getInstructions();
    for(auto const &instruction : instructions){
        
        const auto decodedInstruction = DecodedInstruction_t::factory(instruction);
        
        
        //TODO weiter: weg finden, wie man herausfindet, welche eflags die operation liest: https://www.capstone-engine.org/op_access.html
        
        // only change conditional branch instructions
        if(decodedInstruction->isConditionalBranch()){
            cout << endl << "new inst: ";
            //create capstone class from this!!!
            //const auto opcode = instruction->getDataBits();
            const uint8_t* opcode = reinterpret_cast<const uint8_t*>(instruction->getDataBits().c_str());
            
            count = cs_disasm(handle, opcode, sizeof(opcode)-1, 0x1000, 0, &insn);
            if (count > 0) {
           
                for (size_t j = 0; j < count; j++) {
                // Print assembly
                    printf("%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
                    
                    // Print all registers accessed by this instruction.
                    if (cs_regs_access(handle, &insn[j],
                            regs_read, &read_count,
                            regs_write, &write_count) == 0) {
                        if (read_count > 0) {
                            printf("\n\tRegisters read:");
                            for (i = 0; i < read_count; i++) {
                                printf(" %s", cs_reg_name(handle, regs_read[i]));
                            }
                            printf("\n");
                        }

                        if (write_count > 0) {
                            printf("\n\tRegisters modified:");
                            for (i = 0; i < write_count; i++) {
                                printf(" %s", cs_reg_name(handle, regs_write[i]));
                            }
                            printf("\n");
                        }
                    }
                    auto x86 = &(insn->detail->x86);
                    if(x86->eflags){
                        
                            printf("\tEFLAGS:");
                            for(i = 0; i <= 63; i++)
                                if (x86->eflags & ((uint64_t)1 << i)) {
                                    printf(" %s", get_eflag_name((uint64_t)1 << i));
                                }
                            printf("\n");
		                
                    }
                }
            }

            cs_free(insn, count);
        }
    }
    
    // before each jump, check the shadow memory of the eflags bit used for the jump
    // idea: store registsers where origin tracking would usually be
    // success!
	return true;
}

static const char *get_eflag_name(uint64_t flag)
{
	switch(flag) {
		default:
			return NULL;
		case X86_EFLAGS_UNDEFINED_OF:
			return "UNDEF_OF";
		case X86_EFLAGS_UNDEFINED_SF:
			return "UNDEF_SF";
		case X86_EFLAGS_UNDEFINED_ZF:
			return "UNDEF_ZF";
		case X86_EFLAGS_MODIFY_AF:
			return "MOD_AF";
		case X86_EFLAGS_UNDEFINED_PF:
			return "UNDEF_PF";
		case X86_EFLAGS_MODIFY_CF:
			return "MOD_CF";
		case X86_EFLAGS_MODIFY_SF:
			return "MOD_SF";
		case X86_EFLAGS_MODIFY_ZF:
			return "MOD_ZF";
		case X86_EFLAGS_UNDEFINED_AF:
			return "UNDEF_AF";
		case X86_EFLAGS_MODIFY_PF:
			return "MOD_PF";
		case X86_EFLAGS_UNDEFINED_CF:
			return "UNDEF_CF";
		case X86_EFLAGS_MODIFY_OF:
			return "MOD_OF";
		case X86_EFLAGS_RESET_OF:
			return "RESET_OF";
		case X86_EFLAGS_RESET_CF:
			return "RESET_CF";
		case X86_EFLAGS_RESET_DF:
			return "RESET_DF";
		case X86_EFLAGS_RESET_IF:
			return "RESET_IF";
		case X86_EFLAGS_TEST_OF:
			return "TEST_OF";
		case X86_EFLAGS_TEST_SF:
			return "TEST_SF";
		case X86_EFLAGS_TEST_ZF:
			return "TEST_ZF";
		case X86_EFLAGS_TEST_PF:
			return "TEST_PF";
		case X86_EFLAGS_TEST_CF:
			return "TEST_CF";
		case X86_EFLAGS_RESET_SF:
			return "RESET_SF";
		case X86_EFLAGS_RESET_AF:
			return "RESET_AF";
		case X86_EFLAGS_RESET_TF:
			return "RESET_TF";
		case X86_EFLAGS_RESET_NT:
			return "RESET_NT";
		case X86_EFLAGS_PRIOR_OF:
			return "PRIOR_OF";
		case X86_EFLAGS_PRIOR_SF:
			return "PRIOR_SF";
		case X86_EFLAGS_PRIOR_ZF:
			return "PRIOR_ZF";
		case X86_EFLAGS_PRIOR_AF:
			return "PRIOR_AF";
		case X86_EFLAGS_PRIOR_PF:
			return "PRIOR_PF";
		case X86_EFLAGS_PRIOR_CF:
			return "PRIOR_CF";
		case X86_EFLAGS_PRIOR_TF:
			return "PRIOR_TF";
		case X86_EFLAGS_PRIOR_IF:
			return "PRIOR_IF";
		case X86_EFLAGS_PRIOR_DF:
			return "PRIOR_DF";
		case X86_EFLAGS_TEST_NT:
			return "TEST_NT";
		case X86_EFLAGS_TEST_DF:
			return "TEST_DF";
		case X86_EFLAGS_RESET_PF:
			return "RESET_PF";
		case X86_EFLAGS_PRIOR_NT:
			return "PRIOR_NT";
		case X86_EFLAGS_MODIFY_TF:
			return "MOD_TF";
		case X86_EFLAGS_MODIFY_IF:
			return "MOD_IF";
		case X86_EFLAGS_MODIFY_DF:
			return "MOD_DF";
		case X86_EFLAGS_MODIFY_NT:
			return "MOD_NT";
		case X86_EFLAGS_MODIFY_RF:
			return "MOD_RF";
		case X86_EFLAGS_SET_CF:
			return "SET_CF";
		case X86_EFLAGS_SET_DF:
			return "SET_DF";
		case X86_EFLAGS_SET_IF:
			return "SET_IF";
	}
}