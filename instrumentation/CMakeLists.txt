############### INSTRUMENTATION ###############
add_executable(binmsan
        CapstoneService.cpp
        EflagsHandler.cpp
        JumpHandler.cpp
        MemoryAccessInstrumentation.cpp
        MovHandler.cpp
        MSan.cpp
        Main.cpp
        RuntimeLib.h
        StackVariableHandler.cpp
        Utils.cpp
        ../common/RegisterNumbering.h
        ../common/Width.h
)
target_compile_options(binmsan PRIVATE -Wall -Wextra -Wpedantic)

# add irdb_sdk to instrumentation target
target_link_libraries(
        binmsan PRIVATE irdb-sdk
)

# the .exe postfix is required by the zipr framework
set_target_properties(binmsan PROPERTIES OUTPUT_NAME "binmsan.exe")