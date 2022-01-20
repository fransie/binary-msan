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

#include <assert.h>
#include <iostream>
#include "jumps.hpp"

using namespace IRDB_SDK;
using namespace std;

// constructor
JumpsPass::JumpsPass(FileIR_t *p_variantIR)
	: 
	Transform_t(p_variantIR)
{
}

bool JumpsPass::execute()
{
    // log
    cout << "Log test. Does this appear in the log?" << endl;

    // get one of the first instructions
    const auto instructions=getFileIR()->getInstructions();
    const auto instr = *(instructions.begin());

    // print syscall
    const string print = "    mov rax, 1\n"
                         "    mov rdi, 1\n"
                         "    mov rdx, 8\n"
                         "    mov rsi, 0x00402007\n" // address of success string
                         "    syscall\n";

    // exit syscall
    const string exit = "    mov rsi, 0x000188b8\n" // address of arbitrary string in ls to find it with r2 axt
                        "    mov rax, 0x3c\n"
                        "    syscall\n";

    // insert print message
    const auto newInsns = insertAssemblyInstructionsBefore(instr, print, {});
    //const auto newInsns = insertAssemblyInstructionsBefore(instr, exit, {});

    // success!
	return true;
}