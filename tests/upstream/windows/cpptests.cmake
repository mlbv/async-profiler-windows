# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
# Upstream's C++ unit tests (Makefile target build/test/cpptests). As in upstream's merged build, the
# test sources share one translation unit with the profiler sources (the DLL's amalgam), which lets
# tests reach static functions; the Windows backends are separate units, as in the DLL.

file(GLOB cpp_test_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test/native/*.cpp")
set(cpptests_unit "${amalgam}")
foreach(source IN LISTS cpp_test_sources)
    string(APPEND cpptests_unit "#include \"${source}\"\n")
endforeach()
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/cpptests.cpp" CONTENT "${cpptests_unit}")

add_library(cpptests_unit OBJECT "${CMAKE_CURRENT_BINARY_DIR}/cpptests.cpp")
target_compile_features(cpptests_unit PRIVATE cxx_std_20)
target_compile_definitions(cpptests_unit PRIVATE $<TARGET_PROPERTY:asyncProfiler_core,COMPILE_DEFINITIONS>)
target_include_directories(cpptests_unit PRIVATE $<TARGET_PROPERTY:asyncProfiler_core,INCLUDE_DIRECTORIES> test/native)
target_compile_options(cpptests_unit PRIVATE $<TARGET_PROPERTY:asyncProfiler_core,COMPILE_OPTIONS>)

add_executable(cpptests ${windows_sources} $<TARGET_OBJECTS:cpptests_unit>)
target_compile_features(cpptests PRIVATE cxx_std_20)
target_compile_definitions(cpptests PRIVATE $<TARGET_PROPERTY:asyncProfiler,COMPILE_DEFINITIONS>)
target_include_directories(cpptests PRIVATE $<TARGET_PROPERTY:asyncProfiler,INCLUDE_DIRECTORIES>)
target_compile_options(cpptests PRIVATE $<TARGET_PROPERTY:asyncProfiler,COMPILE_OPTIONS>)
target_link_options(cpptests PRIVATE $<TARGET_PROPERTY:asyncProfiler,LINK_OPTIONS>)
target_link_libraries(cpptests PRIVATE $<TARGET_PROPERTY:asyncProfiler,LINK_LIBRARIES>)
set_target_properties(cpptests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build/test")
add_dependencies(upstream-tests cpptests)
