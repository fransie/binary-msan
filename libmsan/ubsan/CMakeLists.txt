# Build for the undefined behavior sanitizer runtime support library.

set(UBSAN_SOURCES
  ubsan_diag.cpp
  ubsan_init.cpp
  ubsan_flags.cpp
  ubsan_handlers.cpp
  ubsan_monitor.cpp
  ubsan_value.cpp
  ubsan_diag_standalone.cpp
  ubsan_init_standalone.cpp
  ubsan_signals_standalone.cpp
  )

set(UBSAN_CXXABI_SOURCES
  ubsan_handlers_cxx.cpp
  ubsan_type_hash.cpp
  ubsan_type_hash_itanium.cpp
  ubsan_type_hash_win.cpp
 )

set(UBSAN_HEADERS
  ubsan_checks.inc
  ubsan_diag.h
  ubsan_flags.h
  ubsan_flags.inc
  ubsan_handlers.h
  ubsan_handlers_cxx.h
  ubsan_init.h
  ubsan_interface.inc
  ubsan_monitor.h
  ubsan_platform.h
  ubsan_signals_standalone.h
  ubsan_type_hash.h
  ubsan_value.h
  )


add_library(ubsan STATIC
        ${UBSAN_SOURCES}
        ${UBSAN_HEADERS})
add_library(ubsan_cxx STATIC
        ${UBSAN_CXXABI_SOURCES}
        ${UBSAN_HEADERS})

set(MSAN_CFLAGS -Wall -W -Wno-unused-parameter -Wwrite-strings -pedantic -Wno-long-long -fPIC -fno-builtin -fno-exceptions -fno-rtti -fomit-frame-pointer -funwind-tables -fvisibility=hidden -ftls-model=initial-exec -nostdinc++ -Wno-variadic-macros)
target_compile_options(ubsan INTERFACE ${MSAN_CFLAGS})
target_compile_options(ubsan_cxx INTERFACE ${MSAN_CFLAGS})
target_include_directories(ubsan PUBLIC ..)
target_include_directories(ubsan_cxx PUBLIC ..)
