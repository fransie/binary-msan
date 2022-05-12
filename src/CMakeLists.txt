add_library(interface SHARED
        interface.h
        interface.cpp
        )

add_executable(binmsan
        msan.cpp
        interface.cpp
        main.cpp
        CapstoneService.cpp
        utils.cpp
        )

target_compile_options(binmsan PRIVATE -Wall -Wextra -Wpedantic)
target_compile_options(interface PRIVATE -Wall -Wextra -Wpedantic)

# msan libraries do not work yet, uncomment if ready
target_link_libraries(
        binmsan PRIVATE irdb-sdk
        #interface msan_c
        #interface msan_cxx
        )

# the .exe postfix is required by the zipr framework
set_target_properties(binmsan PROPERTIES OUTPUT_NAME "binmsan.exe")
