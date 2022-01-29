#ifndef EFLAGS_ACCESS_H
#define EFLAGS_ACCESS_H

#include <vector>
#include <capstone.h>

namespace Eflags {
	
	enum class Flag { OF, SF, ZF, PF, CF, Else};

	// 
	// Provides access to read and written flags in eflags register.
	//
	class EflagsAccess
	{
		public:
			EflagsAccess();

			std::vector<Flag> get_read_flag(const uint8_t* opcode);

		private:
			csh handle;
			
	};
	
	const Flag get_eflag_name(uint64_t flag);
}
#endif