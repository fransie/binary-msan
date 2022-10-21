############### COUNTER ###############
add_executable(counter
        Main.cpp
        InstrCounter.h
        InstrCounter.cpp
)
target_compile_options(counter PRIVATE -Wall -Wextra -Wpedantic)

# add irdb_sdk to instrumentation target
target_link_libraries(
        counter PRIVATE irdb-sdk
)

# the .exe postfix is required by the zipr framework
set_target_properties(counter PROPERTIES OUTPUT_NAME "counter.exe")