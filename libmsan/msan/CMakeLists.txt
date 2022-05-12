include_directories(..)

# Runtime library sources and build flags.
set(MSAN_RTL_SOURCES
  msan.cpp
  msan_allocator.cpp
  msan_chained_origin_depot.cpp
  msan_interceptors.cpp
  msan_linux.cpp
  msan_report.cpp
  msan_thread.cpp
  msan_poisoning.cpp
  )

set(MSAN_RTL_CXX_SOURCES
  msan_new_delete.cpp
  )

set(MSAN_RTL_HEADERS
  msan.h
  msan_allocator.h
  msan_chained_origin_depot.h
  msan_flags.h
  msan_flags.inc
  msan_interface_internal.h
  msan_origin.h
  msan_poisoning.h
  msan_report.h
  msan_thread.h
  msan_interface.h
  )

# Shared runtime libraries.
add_library(msan SHARED
        ${MSAN_RTL_SOURCES}
        ${MSAN_RTL_HEADERS}
        )
target_link_libraries(msan
        PRIVATE interception
        PRIVATE sanitizer_common
        PRIVATE ubsan
        )

#add_library(msan_cxx SHARED
#        ${MSAN_RTL_CXX_SOURCES}
#        ${MSAN_RTL_HEADERS}
#        )
#target_link_libraries(msan_cxx
#        PRIVATE interception
#        PRIVATE sanitizer_common
#        PRIVATE ubsan_cxx
#        )

# -ftls-model=initial-exec apparently needed to ensure initial-exec, see https://github.com/llvm/llvm-project/blob/75e33f71c2dae584b13a7d1186ae0a038ba98838/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc#L5315
set(MSAN_CFLAGS -Wall -W -Wno-unused-parameter -Wwrite-strings -pedantic -Wno-long-long  -fPIC -fno-builtin -fno-exceptions -fno-rtti -fomit-frame-pointer -funwind-tables -fvisibility=hidden -ftls-model=initial-exec -nostdinc++ -Wno-variadic-macros)
set(MSAN_LINK_FLAGS -nostdlib++)

target_compile_options(msan INTERFACE ${MSAN_CFLAGS})
#target_link_options(msan INTERFACE ${MSAN_LINK_FLAGS})
#target_compile_options(msan_cxx INTERFACE ${MSAN_CFLAGS})
#target_link_options(msan_cxx INTERFACE ${MSAN_LINK_FLAGS})
