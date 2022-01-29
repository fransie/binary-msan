#ifndef EFLAGS_ACCESS_H
#define EFLAGS_ACCESS_H

#include <vector>
#include <capstone.h>

namespace Eflags {
	
	enum class Flag { OF, SF, ZF, PF, CF, Else};

	/**
	 * Provides access to information about which flags in the EFLAFS register
	 * have been read by an instruction.
	 * 
	 */
	class EflagsAccess
	{
		public:
			/**
			 * Constructor. Initializes capstone handle with detailed disassembly.
			 */
			EflagsAccess();

			/**
			 * Returns which flags of the EFLAGS register have been read by a
			 * conditionally branching instruction.
			 * 
			 * @param opcode uint8_t pointer to opcode of one conditionally branching assembly instruction, e.g. je or jnz
			 * @return std::vector<Flag> contains all Flags that have been read by the instruction.
			 * 			If the instruction is not a conditional branch, Flag::Else might be contained once or multiple times.
			 */
			std::vector<Flag> get_read_flag(const uint8_t* opcode);

		private:
			csh handle;
			
	};
	
	const Flag get_eflag_name(uint64_t flag);
}
#endif