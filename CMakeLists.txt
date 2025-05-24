# CMake project for OptiPNG
#
# Copyright (C) 2025 Cosmin Truta and the Contributing Authors.
#
# OptiPNG is open-source software, distributed under the zlib license.
# Please see the accompanying LICENSE file.

cmake_minimum_required(VERSION 3.15...4.0)

project(OptiPNG
        VERSION 7.9.1
        DESCRIPTION "Advanced PNG optimizer"
        LANGUAGES C
)

#
# Public options
#

option(OPTIPNG_USE_SYSTEM_LIBS "Use the system libraries" OFF)

if(OPTIPNG_USE_SYSTEM_LIBS)
  option(OPTIPNG_USE_SYSTEM_PNG "Use the system libpng" ON)
  option(OPTIPNG_USE_SYSTEM_ZLIB "Use the system zlib" ON)
else()
  option(OPTIPNG_USE_SYSTEM_PNG "Use the system libpng" OFF)
  option(OPTIPNG_USE_SYSTEM_ZLIB "Use the system zlib" OFF)
endif()

option(OPTIPNG_BUILD_TESTS "Build the unit test programs" ON)

if(OPTIPNG_USE_SYSTEM_LIBPNG)
  message(FATAL_ERROR
          "Incorrect option: OPTIPNG_USE_SYSTEM_LIBPNG=${OPTIPNG_USE_SYSTEM_LIBPNG} "
          "(did you mean OPTIPNG_USE_SYSTEM_PNG=${OPTIPNG_USE_SYSTEM_LIBPNG})?"
  )
endif()
if(OPTIPNG_USE_SYSTEM_PNG AND NOT OPTIPNG_USE_SYSTEM_ZLIB)
  message(FATAL_ERROR
          "Incorrect option combination: "
          "OPTIPNG_USE_SYSTEM_PNG=${OPTIPNG_USE_SYSTEM_PNG} "
          "OPTIPNG_USE_SYSTEM_ZLIB=${OPTIPNG_USE_SYSTEM_ZLIB} "
          "(cannot use the system libpng without the system zlib)"
  )
endif()

#
# Other options
#

if(MSVC)
  if(CMAKE_MSVC_RUNTIME_LIBRARY)
    message(STATUS "Using the MSVC ${CMAKE_MSVC_RUNTIME_LIBRARY} runtime")
  else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    message(STATUS "Using the MSVC MultiThreadedDLL runtime")
  endif()
endif()

#
# File lists
#

set(OPTIPNG_SOURCE_DIRECTORIES src/optipng third_party/cexcept)
set(OPTIPNG_SOURCES
    src/optipng/optipng.c
    src/optipng/optim.c
    src/optipng/bitset.c
    src/optipng/ioutil.c
    src/optipng/ratio.c
)
set(OPTIPNG_HEADERS
    src/optipng/optipng.h
    src/optipng/bitset.h
    src/optipng/ioutil.h
    src/optipng/ratio.h
)
if(WIN32)
  list(APPEND OPTIPNG_SOURCE_DIRECTORIES third_party/wildargs)
  list(APPEND OPTIPNG_SOURCES third_party/wildargs/wildargs.c)
  # TODO: Add third_party/wildargs/CMakeLists.txt
endif()
list(APPEND OPTIPNG_HEADERS third_party/cexcept/cexcept.h)
# TODO: Add third_party/cexcept/CMakeLists.txt

set(OPNGREDUC_SOURCE_DIRECTORIES src/opngreduc)
set(OPNGREDUC_SOURCES src/opngreduc/opngreduc.c)
set(OPNGREDUC_HEADERS src/opngreduc/opngreduc.h)

set(PNGXTERN_SOURCE_DIRECTORIES src/pngxtern)
set(PNGXTERN_SOURCES
    src/pngxtern/pngxio.c
    src/pngxtern/pngxmem.c
    src/pngxtern/pngxset.c
    src/pngxtern/pngxread.c
    src/pngxtern/pngxrbmp.c
    src/pngxtern/pngxrgif.c
    src/pngxtern/pngxrjpg.c
    src/pngxtern/pngxrpnm.c
    src/pngxtern/pngxrtif.c
)
set(PNGXTERN_HEADERS
    src/pngxtern/pngxtern.h
    src/pngxtern/pngxutil.h
)

#
# Libraries
#

set(OPTIPNG_LINK_LIBRARIES)

if(NOT OPTIPNG_USE_SYSTEM_ZLIB)
  set(OPTIPNG_VENDORING_ZLIB_EXTRAS "${CMAKE_SOURCE_DIR}/third_party/vendoring/zlib_extras")
  list(PREPEND CMAKE_MODULE_PATH "${OPTIPNG_VENDORING_ZLIB_EXTRAS}")
endif()
find_package(ZLIB REQUIRED)
set(OPTIPNG_LINK_LIBRARIES ZLIB::ZLIB ${OPTIPNG_LINK_LIBRARIES})

if(NOT OPTIPNG_USE_SYSTEM_PNG)
  set(OPTIPNG_VENDORING_PNG_EXTRAS "${CMAKE_SOURCE_DIR}/third_party/vendoring/libpng_extras")
  list(PREPEND CMAKE_MODULE_PATH "${OPTIPNG_VENDORING_PNG_EXTRAS}")
endif()
find_package(PNG REQUIRED)
set(OPTIPNG_LINK_LIBRARIES PNG::PNG ${OPTIPNG_LINK_LIBRARIES})

add_subdirectory(third_party/gifread gifread)
add_subdirectory(third_party/minitiff minitiff)
add_subdirectory(third_party/pnmio pnmio)
set(OPTIPNG_LINK_LIBRARIES gifread minitiff pnmio ${OPTIPNG_LINK_LIBRARIES})

#
# Targets
#

add_executable(
    optipng
    ${OPTIPNG_SOURCES}
    ${OPTIPNG_HEADERS}
    ${OPNGREDUC_SOURCES}
    ${OPNGREDUC_HEADERS}
    ${PNGXTERN_SOURCES}
    ${PNGXTERN_HEADERS}
)

target_link_libraries(
    optipng
    PRIVATE ${OPTIPNG_LINK_LIBRARIES}
)

target_include_directories(
    optipng
    PRIVATE ${OPTIPNG_SOURCE_DIRECTORIES}
            ${OPNGREDUC_SOURCE_DIRECTORIES}
            ${PNGXTERN_SOURCE_DIRECTORIES}
)

#
# Testing
#

if(OPTIPNG_BUILD_TESTS)
  enable_testing()

  # Smoke-test the optipng program.
  add_test(
      NAME optipng_help_and_version_test
      COMMAND optipng --help --version
  )
  add_test(
      NAME optipng_smoke_test
      COMMAND optipng -o1
                      --clobber
                      --out=pngtest.out.png
                      "${CMAKE_CURRENT_SOURCE_DIR}/src/optipng/testimg/pngtest.png"
  )

  # Test the bitset module.
  add_executable(
      optipng_bitset_test
      src/optipng/testprog/bitset_test.c
      src/optipng/bitset.c
      src/optipng/bitset.h
  )
  target_include_directories(
      optipng_bitset_test
      PRIVATE src/optipng
  )
  add_test(
      NAME optipng_bitset_test
      COMMAND optipng_bitset_test
  )

  # Test the ratio module.
  add_executable(
      optipng_ratio_test
      src/optipng/testprog/ratio_test.c
      src/optipng/ratio.c
      src/optipng/ratio.h
  )
  target_include_directories(
      optipng_ratio_test
      PRIVATE src/optipng
  )
  add_test(
      NAME optipng_ratio_test
      COMMAND optipng_ratio_test
  )
endif()

#
# Installation
#

include(GNUInstallDirs)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/optipng"
        DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/optipng/man/optipng.1"
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
)
