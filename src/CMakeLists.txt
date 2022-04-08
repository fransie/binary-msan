add_library(interface SHARED
        interface.h
        interface.cpp
        )

add_executable(msan
        eflags_access.cpp
        eflags_access.hpp
        jumps.cpp
        jumps.hpp
        msan.cpp
        msan.hpp
        interface.h
        interface.cpp
        main.cpp
        )

target_link_libraries(
        msan PRIVATE irdb-sdk
        )

# the .exe postfix is required by the zipr framework
set_target_properties(msan PROPERTIES OUTPUT_NAME "msan.exe")
