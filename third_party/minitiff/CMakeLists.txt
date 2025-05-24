cmake_minimum_required(VERSION 3.14...4.0)

project(minitiff
        VERSION 0.3
        DESCRIPTION "Minimal I/O interface to the Tagged Image File Format (TIFF)"
        LANGUAGES C
)

# Declare the public build options.
option(MINITIFF_BUILD_STATIC_LIBRARY "Build minitiff as a static library" ON)
option(MINITIFF_BUILD_SHARED_LIBRARY "Build minitiff as a shared library" OFF)
option(MINITIFF_BUILD_TESTS "Build the minitiff test programs" ON)

# Initialize the private build options.
if(${MINITIFF_BUILD_STATIC_LIBRARY} AND NOT ${MINITIFF_BUILD_SHARED_LIBRARY})
  set(MINITIFF_LIBRARY_TYPE STATIC)
elseif(${MINITIFF_BUILD_SHARED_LIBRARY} AND NOT ${MINITIFF_BUILD_STATIC_LIBRARY})
  # TODO: set(MINITIFF_LIBRARY_TYPE SHARED)
  message(SEND_ERROR
          "Unsupported option: "
          "MINITIFF_BUILD_SHARED_LIBRARY=${MINITIFF_BUILD_SHARED_LIBRARY} "
          "(the minitiff API is unstable)"
  )
else()
  message(SEND_ERROR
          "Incorrect option mix: "
          "MINITIFF_BUILD_STATIC_LIBRARY=${MINITIFF_BUILD_STATIC_LIBRARY}, "
          "MINITIFF_BUILD_SHARED_LIBRARY=${MINITIFF_BUILD_SHARED_LIBRARY}"
  )
endif()

# Build the minitiff library.
add_library(
    minitiff
    ${MINITIFF_LIBRARY_TYPE}
    tiffread.c
    tiffutil.c
    #tiffwrite.c
    minitiff.h
)
target_include_directories(
    minitiff
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)

# Build and run the minitiff tests.
if(${MINITIFF_BUILD_TESTS})
  enable_testing()
  add_executable(tiff2pnm testprog/tiff2pnm.c)
  target_link_libraries(tiff2pnm PRIVATE minitiff)
  # TODO: add_test(tiff2pnm ...)
endif()
