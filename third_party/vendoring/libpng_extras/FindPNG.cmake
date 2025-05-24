# FindPNG.cmake
# Find and use the local (vendored) libpng library.

# Copyright (C) 2025 Cosmin Truta
#
# Use, modification and distribution are subject to
# either the PNG Reference Library License version 2
# or the Zlib License.
#
# SPDX-License-Identifier: libpng-2.0 OR zlib

if(TARGET PNG::PNG)
  return()
endif()

set(OPTIPNG_PNG_SUBDIR "${CMAKE_CURRENT_LIST_DIR}/../../libpng")
set(OPTIPNG_PNG_LIBRARY png_static)
if(APPLE AND CMAKE_OSX_ARCHITECTURES)
  string(TOLOWER "${CMAKE_OSX_ARCHITECTURES}" OPTIPNG_TARGET_ARCHITECTURE)
else()
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" OPTIPNG_TARGET_ARCHITECTURE)
endif()
message(STATUS "Building for target architecture: ${OPTIPNG_TARGET_ARCHITECTURE}")
if(${OPTIPNG_TARGET_ARCHITECTURE} MATCHES "^(aarch64|arm64)"
   OR ${OPTIPNG_TARGET_ARCHITECTURE} MATCHES "^(amd64|x86_64)"
   # TODO: Check more target architectures.
)
  set(OPTIPNG_PNG_HARDWARE_OPTIMIZATIONS_DEFAULT ON)
else()
  set(OPTIPNG_PNG_HARDWARE_OPTIMIZATIONS_DEFAULT OFF)
endif()

# TODO:
# Refine the initialization of OPTIPNG_PNG_HARDWARE_OPTIMIZATIONS_DEFAULT,
# which is conservatively safe, but rather crude. If the user wants to adjust
# PNG_HARDWARE_OPTIMIZATIONS on architectures outside of Aarch64 and AMD64,
# they should keep in mind that the run-time checking of SIMD availability is
# currently disabled.

# Build the statically-linked libpng library, alias it to PNG::PNG,
# and assign it to PNG_LIBRARIES.
option(PNG_STATIC "Build the static libpng library" ON)
option(PNG_SHARED "Build the shared libpng library" OFF)
option(PNG_FRAMEWORK "Build the libpng framework (Darwin only)" OFF)
option(PNG_TOOLS "Build the libpng tools" OFF)
option(PNG_HARDWARE_OPTIMIZATIONS
       "Enable the hardware (SIMD) optimizations in libpng"
       ${OPTIPNG_PNG_HARDWARE_OPTIMIZATIONS_DEFAULT}
)
if(PNG_HARDWARE_OPTIMIZATIONS)
  set(PNG_LIBCONF_HEADER "${CMAKE_CURRENT_LIST_DIR}/pnglibconf_optipng_simd.h")
else()
  set(PNG_LIBCONF_HEADER "${CMAKE_CURRENT_LIST_DIR}/pnglibconf_optipng_nosimd.h")
endif()
set(SKIP_INSTALL_ALL TRUE)
add_subdirectory("${OPTIPNG_PNG_SUBDIR}" libpng)
add_library(PNG::PNG ALIAS ${OPTIPNG_PNG_LIBRARY})
set(PNG_LIBRARIES ${OPTIPNG_PNG_LIBRARY})

# Define PNG_SOURCE_DIR and PNG_INCLUDE_DIR, and ensure that png.h
# is where it should be.
get_target_property(PNG_SOURCE_DIR PNG::PNG SOURCE_DIR)
if(NOT PNG_SOURCE_DIR)
  set(PNG_SOURCE_DIR "${OPTIPNG_PNG_SUBDIR}")
endif()
find_path(PNG_INCLUDE_DIR
          NAMES png.h
          PATHS "${PNG_SOURCE_DIR}"
          NO_DEFAULT_PATH
)
if(NOT PNG_INCLUDE_DIR)
  message(FATAL_ERROR "Could not find png.h in \"${PNG_SOURCE_DIR}\"")
endif()

# So, we found PNG!
set(PNG_FOUND TRUE)
message(STATUS "Using vendored PNG: ${PNG_SOURCE_DIR}")
