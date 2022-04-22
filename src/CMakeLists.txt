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
        CapstoneService.cpp
        utils.cpp
        )

# TODO: Fix absolute path
# path to libraries that should be linked into the interface library
target_link_directories(interface PUBLIC "/home/franzi/Documents/binary-msan2/sharedlibrary")

# msan libraries do not work yet, uncomment if ready
target_link_libraries(
        msan PRIVATE irdb-sdk
        #interface msan_c
        #interface msan_cxx
        )

# the .exe postfix is required by the zipr framework
set_target_properties(msan PROPERTIES OUTPUT_NAME "msan.exe")
