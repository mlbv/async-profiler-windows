# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
# Windows builds of upstream's test libraries and test programs (upstream Makefile targets
# build-test-libs and build-test-bins), placed where upstream's runner expects them.
# Included by core/CMakeLists.txt with ASPROF_UPSTREAM_TESTS=ON; run.ps1 drives it.

get_filename_component(compiler_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
set(CMAKE_C_COMPILER "${compiler_dir}/clang.exe")
set(CMAKE_C_COMPILER_TARGET "${CMAKE_CXX_COMPILER_TARGET}")
enable_language(C)

set(test_lib_dir "${CMAKE_CURRENT_SOURCE_DIR}/build/test/lib")
set(test_bin_dir "${CMAKE_CURRENT_SOURCE_DIR}/build/test/bin")

add_custom_target(upstream-tests)

# CodeView PDBs let the profiler's DbgHelp symbolizer name functions that are not exported.
function(upstream_test_target target output_dir)
    set_target_properties(${target} PROPERTIES PREFIX "" RUNTIME_OUTPUT_DIRECTORY "${output_dir}")
    target_include_directories(${target} PRIVATE windows/include "${JAVA_HOME}/include" "${JAVA_HOME}/include/win32")
    target_compile_options(${target} PRIVATE -gcodeview)
    target_link_options(${target} PRIVATE -fuse-ld=lld -Wl,--pdb= -static -pthread)
    add_dependencies(upstream-tests ${target})
endfunction()

function(upstream_test_lib target)
    add_library(${target} SHARED ${ARGN})
    upstream_test_target(${target} "${test_lib_dir}")
endfunction()

function(upstream_test_bin target)
    add_executable(${target} ${ARGN})
    upstream_test_target(${target} "${test_bin_dir}")
    target_include_directories(${target} PRIVATE ../../core/src test/native)
endfunction()

upstream_test_lib(processid windows/processid.c)
upstream_test_lib(alignedalloc windows/alignedalloc.c)
upstream_test_lib(libcallsmalloc test/native/libs/callsmalloc.c)
upstream_test_lib(jnimalloc test/native/libs/jnimalloc.c)
target_link_libraries(jnimalloc PRIVATE alignedalloc)
upstream_test_lib(jninativestacks test/native/libs/jninativestacks.c)
target_compile_options(jninativestacks PRIVATE -fno-optimize-sibling-calls)
upstream_test_lib(jninativelocks test/native/libs/jninativelocks_windows.c)
upstream_test_lib(libmalloc test/native/libs/malloc_windows.c)

upstream_test_bin(malloc_plt_dyn test/test/nativemem/malloc_plt_dyn.c)
upstream_test_bin(native_api test/test/c/native_api.c)
upstream_test_bin(native_lock_contention test/test/nativelock/native_lock_contention_windows.c)
upstream_test_bin(profile_with_dlopen test/test/nativemem/profile_with_dlopen.c)
upstream_test_bin(nativemem_known_lib_crash test/test/nativemem/nativemem_known_lib_crash.c)
upstream_test_bin(preload_malloc test/test/nativemem/preload_malloc.c)
upstream_test_bin(non_java_app test/test/nonjava/non_java_app.cpp)
target_compile_features(non_java_app PRIVATE cxx_std_11)
include(windows/cpptests.cmake)
