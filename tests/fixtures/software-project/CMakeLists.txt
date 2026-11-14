# SPDX-License-Identifier: MPL-2.0
cmake_minimum_required(VERSION 3.20)
project(FileVeilCopyrightFixture C CXX)
add_executable(fileveil-fixture main.c)
set_target_properties(fileveil-fixture PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/dist")
enable_testing()
add_test(NAME normal COMMAND fileveil-fixture 7)
set_tests_properties(normal PROPERTIES PASS_REGULAR_EXPRESSION "result=50")
add_test(NAME negative COMMAND fileveil-fixture -3)
set_tests_properties(negative PROPERTIES PASS_REGULAR_EXPRESSION "result=10")

add_executable(fileveil-cpp main.cpp)
set_target_properties(fileveil-cpp PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/dist")
add_test(NAME cpp_normal COMMAND fileveil-cpp 7)
set_tests_properties(cpp_normal PROPERTIES PASS_REGULAR_EXPRESSION "result=50")
add_test(NAME cpp_negative COMMAND fileveil-cpp -3)
set_tests_properties(cpp_negative PROPERTIES PASS_REGULAR_EXPRESSION "result=10")
