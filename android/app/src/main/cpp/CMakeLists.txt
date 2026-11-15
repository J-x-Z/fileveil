# SPDX-License-Identifier: MPL-2.0
cmake_minimum_required(VERSION 3.22.1)
project(fileveil_jni C)
add_library(fileveil_android SHARED IMPORTED)
set_target_properties(fileveil_android PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libfileveil_android.so" IMPORTED_NO_SONAME TRUE)
add_library(fileveil_jni SHARED bridge.c)
target_compile_options(fileveil_jni PRIVATE -Wall -Wextra -Werror -fvisibility=hidden)
target_link_options(fileveil_jni PRIVATE "-Wl,-z,max-page-size=16384")
target_link_libraries(fileveil_jni fileveil_android)

