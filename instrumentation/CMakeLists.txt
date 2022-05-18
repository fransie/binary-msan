############### INSTRUMENTATION ###############
add_executable(binmsan
        msan.cpp
        main.cpp
        CapstoneService.cpp
        utils.cpp
)
target_compile_options(binmsan PRIVATE -Wall -Wextra -Wpedantic)

# add irdb_sdk to instrumentation target
target_link_libraries(
        binmsan PRIVATE irdb-sdk
)

# the .exe postfix is required by the zipr framework
set_target_properties(binmsan PROPERTIES OUTPUT_NAME "binmsan.exe")