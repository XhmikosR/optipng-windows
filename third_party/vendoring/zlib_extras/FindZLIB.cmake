# FindZLIB.cmake
# Find and use the local (vendored) ZLIB library.

# Copyright (C) 2025 Cosmin Truta
#
# Use, modification and distribution are subject to
# the Zlib License.
#
# SPDX-License-Identifier: zlib

if(TARGET ZLIB::ZLIB)
  return()
endif()

set(OPTIPNG_ZLIB_SUBDIR "${CMAKE_CURRENT_LIST_DIR}/../../zlib")
set(OPTIPNG_ZLIB_LIBRARY zlibstatic)

# Build the statically-linked zlib library, alias it to ZLIB::ZLIB,
# and assign it to ZLIB_LIBRARIES. Ignore variables such as ZLIB_ROOT
# and ZLIB_LIBRARY that would normally have influenced the effects of
# the standard FindZLIB.cmake module.
#
# TODO:
# option(ZLIB_BUILD_STATIC "Build the static zlib library" ON)
# option(ZLIB_BUILD_SHARED "Build the shared zlib library" OFF)
add_subdirectory("${OPTIPNG_ZLIB_SUBDIR}" zlib)
add_library(ZLIB::ZLIB ALIAS ${OPTIPNG_ZLIB_LIBRARY})
set(ZLIB_LIBRARIES ${OPTIPNG_ZLIB_LIBRARY})

# Define ZLIB_SOURCE_DIR and ZLIB_INCLUDE_DIR, and ensure that zlib.h
# is where it should be.
get_target_property(ZLIB_SOURCE_DIR ZLIB::ZLIB SOURCE_DIR)
if(NOT ZLIB_SOURCE_DIR)
  set(ZLIB_SOURCE_DIR "${OPTIPNG_ZLIB_SUBDIR}")
endif()
find_path(ZLIB_INCLUDE_DIR
          NAMES zlib.h
          PATHS "${ZLIB_SOURCE_DIR}"
          NO_DEFAULT_PATH
)
if(NOT ZLIB_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find zlib.h in \"${ZLIB_SOURCE_DIR}\"")
endif()

# So, we found ZLIB!
set(ZLIB_FOUND TRUE)
message(STATUS "Using vendored ZLIB: ${ZLIB_SOURCE_DIR}")
