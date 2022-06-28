############### INSTRUMENTATION ###############
add_executable(binmsan
        CapstoneService.cpp
        Handler.h
        JumpHandler.cpp
        MemoryAccessInstrumentation.cpp
        MovHandler.cpp
        MSan.cpp
        Main.cpp
        RuntimeLib.h
        TestHandler.cpp
        Utils.cpp
        ../common/Width.h
)
target_compile_options(binmsan PRIVATE -Wall -Wextra -Wpedantic)

# add irdb_sdk to instrumentation target
target_link_libraries(
        binmsan PRIVATE irdb-sdk
)

# the .exe postfix is required by the zipr framework
set_target_properties(binmsan PROPERTIES OUTPUT_NAME "binmsan.exe")