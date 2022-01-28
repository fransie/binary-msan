#   
#   Copyright 2017-2019 University of Virginia
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#


#
# Scons is python based.  We import OS to get at the environment.
#
import os


#
# create a basic scons environment
#
env=Environment()

#
# Include environment variables.  These lines throw semi-readable errors if the environment is not defined properly.
#
env.Replace(COOKBOOK_HOME=os.environ['COOKBOOK_HOME']) # add cookbook home var to env. for other scons files
env.Replace(IRDB_SDK=     os.environ['IRDB_SDK']     ) # IRDB_SDK and IRDB_LIB by convention to find headers and libraries.
env.Replace(IRDB_LIBS=    os.environ['IRDB_LIBS']    ) 
env.Replace(CAPSTONE=     os.environ['CAPSTONE'])      # make CAPSTONE env variable available as well

#
# Check for "debug=1" on the scons command line
#
env.Replace(debug=ARGUMENTS.get("debug",0))   # build in debug mode?

#
# Required:  need these flag to appropriately include/link IRDB files.
#
env.Append(CXXFLAGS=" -std=c++11 ")	# enable c++11
env.Append(LINKFLAGS=" -Wl,-unresolved-symbols=ignore-in-shared-libs ") # irdb libs may have symbols that resolve OK at runtime, but not linktime.


# if we are building in debug mode, use -g, else use -O
if int(env['debug']) == 1:
        env.Append(CFLAGS=     " -g ")
        env.Append(CXXFLAGS=   " -g ")
        env.Append(LINKFLAGS=  " -g ")
        env.Append(SHLINKFLAGS=" -g ")
else:
        env.Append(CFLAGS=     " -O ")
        env.Append(CXXFLAGS=   " -O ")
        env.Append(LINKFLAGS=  " -O ")
        env.Append(SHLINKFLAGS=" -O ")


Export('env')
SConscript("SConscript", variant_dir='build')

