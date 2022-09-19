############### INSTRUMENTATION ###############
add_executable(binmsan_instrumentation
        BinaryArithmeticHandler.cpp
        BinaryLogicHandler.cpp
        DisassemblyService.cpp
        EflagsHandler.cpp
        FunctionAnalysis.cpp
        ControlFlowHandler.cpp
        LeaHandler.cpp
        MemoryAccessHandler.cpp
        MovHandler.cpp
        MSan.cpp
        Main.cpp
        RuntimeLib.h
        StackVariableHandler.cpp
        Utils.cpp
        ../common/RegisterNumbering.h
        ../common/Width.h
)
target_compile_options(binmsan_instrumentation PRIVATE -Wall -Wextra -Wpedantic)

# add irdb_sdk to instrumentation target
target_link_libraries(
        binmsan_instrumentation PRIVATE irdb-sdk
)

# the .exe postfix is required by the zipr framework
set_target_properties(binmsan_instrumentation PROPERTIES OUTPUT_NAME "binmsan_instrumentation.exe")