cmake_minimum_required(VERSION 3.14...4.0)

project(pnmio
        VERSION 0.4
        DESCRIPTION "I/O interface to the Portable Any Map (PNM) image format"
        LANGUAGES C
)

# Declare the public build options.
option(PNMIO_BUILD_STATIC_LIBRARY "Build pnmio as a static library" ON)
option(PNMIO_BUILD_SHARED_LIBRARY "Build pnmio as a shared library" OFF)
# TODO: option(PNMIO_BUILD_TESTS "Build the pnmio test programs" ON)

# Initialize the private build options.
if(${PNMIO_BUILD_STATIC_LIBRARY} AND NOT ${PNMIO_BUILD_SHARED_LIBRARY})
  set(PNMIO_LIBRARY_TYPE STATIC)
elseif(${PNMIO_BUILD_SHARED_LIBRARY} AND NOT ${PNMIO_BUILD_STATIC_LIBRARY})
  # TODO: set(PNMIO_LIBRARY_TYPE SHARED)
  message(SEND_ERROR
          "Unsupported option: "
          "PNMIO_BUILD_SHARED_LIBRARY=${PNMIO_BUILD_SHARED_LIBRARY} "
          "(the ${PROJECT_NAME} API is unstable)"
  )
else()
  message(SEND_ERROR
          "Incorrect option mix: "
          "PNMIO_BUILD_STATIC_LIBRARY=${PNMIO_BUILD_STATIC_LIBRARY}, "
          "PNMIO_BUILD_SHARED_LIBRARY=${PNMIO_BUILD_SHARED_LIBRARY}"
  )
endif()

# Initialize the source lists.
set(PNMIO_SOURCES pnmin.c pnmout.c pnmutil.c)
set(PNMIO_HEADERS pnmio.h)

# Build the pnmio library.
add_library(
    pnmio
    ${PNMIO_LIBRARY_TYPE}
    ${PNMIO_SOURCES}
    ${PNMIO_HEADERS}
)
target_include_directories(
    pnmio
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)
