# SPDX-License-Identifier: MPL-2.0
cmake_minimum_required(VERSION 3.20)
project(FileVeilSoftwareWatermark LANGUAGES C CXX)
find_package(LLVM REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
add_llvm_pass_plugin(FileVeilWatermark FileVeilWatermark.cpp)
target_compile_features(FileVeilWatermark PRIVATE cxx_std_17)
target_include_directories(FileVeilWatermark SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(FileVeilWatermark PRIVATE ${LLVM_DEFINITIONS})
file(GENERATE OUTPUT "$<TARGET_FILE_DIR:FileVeilWatermark>/fileveil-plugin.json" CONTENT
  "{\n  \"schema\": \"fileveil.software.llvm-plugin.v1\",\n  \"llvm_version\": \"${LLVM_PACKAGE_VERSION}\",\n  \"llvm_major\": ${LLVM_VERSION_MAJOR},\n  \"platform\": \"${CMAKE_SYSTEM_NAME}\",\n  \"architecture\": \"${CMAKE_SYSTEM_PROCESSOR}\",\n  \"plugin\": \"$<TARGET_FILE_NAME:FileVeilWatermark>\"\n}\n")
