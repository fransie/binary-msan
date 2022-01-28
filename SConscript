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

import os

#
# import the environment and clone it so we can make changes.
#
Import('env')
irdb_env=env.Clone()

# 
# These settings are recommended, but you can choose what you like
#
irdb_env.Append(CXXFLAGS=" -Wall -Werror -fmax-errors=2 "           ) # be strict about syntax/warnings
irdb_env.Append(LIBS=    Split("irdb-core irdb-transform"          )) # link against core and transform libraries
irdb_env.Append(CPPPATH= " $IRDB_SDK/include:$CAPSTONE"             ) # be able to include the SDK and capstone files
irdb_env.Append(LIBPATH= Split(" $IRDB_LIBS "                      )) # this is where the libraries are.
irdb_env.Replace(INSTALL_PATH=os.environ['PWD']+"/plugins_install"  ) # this is where to place plugins.

#
# export the new environment for children sub-conscripts
#
Export('irdb_env')

#
# include the children sconscript files.
#
dirs=Split("jumps test_pass")
libs = list() 
for dir in dirs:
	libs = libs + irdb_env.SConscript(dir+"/SConscript")

#
# And we are done
#
Return('libs')
