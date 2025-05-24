cmake_minimum_required(VERSION 3.5...4.0)

project(gifread C)

option(GIFREAD_BUILD_TESTS "Build the gifread test programs" ON)

add_library(
    gifread
    STATIC gifread.c gifread.h
)

target_include_directories(
    gifread
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)

if(${GIFREAD_BUILD_TESTS})
  enable_testing()
  add_executable(gifdump testprog/gifdump.c)
  target_link_libraries(
      gifdump
      PRIVATE gifread
  )
  add_test(
      NAME dump_compass_gif
      COMMAND gifdump "${CMAKE_CURRENT_SOURCE_DIR}/testimg/compass.gif"
  )
endif()
