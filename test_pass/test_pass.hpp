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

#ifndef _LIBTRANSFORM_TEST_PASS_H
#define _LIBTRANSFORM_TEST_PASS_H

#include <irdb-core>
#include <irdb-transform>
#include <irdb-deep>

// 
// A simple class that overwrites any dead regiters.  
// This is useful for demonstrating how to obtain a list of dead registers.
// Also useful for testing if dead registers are correct.
//
// Note:  This elides creating a new namespace or "using" the IRDB_SDK namespace,
//  so references to the IRDB_SDK classes must be explicitly scoped.
//
class TestPass : protected IRDB_SDK::Transform_t
{
	public:
		// construct the object, basically no parameters other than the IR to transform
		TestPass(IRDB_SDK::FileIR_t *p_variantIR);


		// actually perform the transform
		bool execute();

	private:
		// no class member data or methods yet.
};

#endif
