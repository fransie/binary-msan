#include "eflags_access.hpp"
#include "capstone.h"
#include <iostream>


Eflags::EflagsAccess::EflagsAccess(){
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
        //TODO: error handling
    }
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

std::vector<Eflags::Flag> Eflags::EflagsAccess::get_read_flag(const uint8_t* opcode){
    cs_insn *insn;
	//TODO: error handling of cs_disasm
    size_t count = cs_disasm(handle, opcode, sizeof(opcode)-1, 0x1000, 0, &insn);
	if (count == 0){
		std::cout << "ERROR";
	}
	auto x86 = &(insn->detail->x86);
	std::vector<Flag> flags; 
	if(x86->eflags){
		for(auto i = 0; i <= 63; i++){
			if (x86->eflags & ((uint64_t)1 << i)) {
				flags.push_back(get_eflag_name((uint64_t)1 << i));
			}
		}	
	}
    cs_free(insn, count);
	return flags;
}

const Eflags::Flag Eflags::get_eflag_name(uint64_t flag)
{
	switch(flag) {
        //TODO: check if non-TEST cases can be deleted
		default:
			return Flag::Else;
		case X86_EFLAGS_UNDEFINED_OF:
			return Flag::Else;
		case X86_EFLAGS_UNDEFINED_SF:
			return Flag::Else;
		case X86_EFLAGS_UNDEFINED_ZF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_AF:
			return Flag::Else;
		case X86_EFLAGS_UNDEFINED_PF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_CF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_SF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_ZF:
			return Flag::Else;
		case X86_EFLAGS_UNDEFINED_AF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_PF:
			return Flag::Else;
		case X86_EFLAGS_UNDEFINED_CF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_OF:
			return Flag::Else;
		case X86_EFLAGS_RESET_OF:
			return Flag::Else;
		case X86_EFLAGS_RESET_CF:
			return Flag::Else;
		case X86_EFLAGS_RESET_DF:
			return Flag::Else;
		case X86_EFLAGS_RESET_IF:
			return Flag::Else;
		case X86_EFLAGS_TEST_OF:
			return Flag::OF;
		case X86_EFLAGS_TEST_SF:
			return Flag::SF;
		case X86_EFLAGS_TEST_ZF:
			return Flag::ZF;
		case X86_EFLAGS_TEST_PF:
			return Flag::PF;
		case X86_EFLAGS_TEST_CF:
			return Flag::CF;
		case X86_EFLAGS_RESET_SF:
			return Flag::Else;
		case X86_EFLAGS_RESET_AF:
			return Flag::Else;
		case X86_EFLAGS_RESET_TF:
			return Flag::Else;
		case X86_EFLAGS_RESET_NT:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_OF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_SF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_ZF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_AF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_PF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_CF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_TF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_IF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_DF:
			return Flag::Else;
		case X86_EFLAGS_TEST_NT:
			return Flag::Else;
		case X86_EFLAGS_TEST_DF:
			return Flag::Else;
		case X86_EFLAGS_RESET_PF:
			return Flag::Else;
		case X86_EFLAGS_PRIOR_NT:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_TF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_IF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_DF:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_NT:
			return Flag::Else;
		case X86_EFLAGS_MODIFY_RF:
			return Flag::Else;
		case X86_EFLAGS_SET_CF:
			return Flag::Else;
		case X86_EFLAGS_SET_DF:
			return Flag::Else;
		case X86_EFLAGS_SET_IF:
			return Flag::Else;
	}
}