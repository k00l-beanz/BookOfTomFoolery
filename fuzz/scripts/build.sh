#!/bin/bash
# Template build script which fuzzing a library
#

AFL_USE_ASAN=1
CC=afl-clang-lto
CXX=afl-clang-lto++
CFLAGS="-fsanitize=address,fuzzer"
CXXFLAGS="-fsanitize=address,fuzzer"

# compiling a harness
bin="harness"
$CXX $CXXFLAGS "${bin}.c" -o $bin -I../src/include/ ../src/.libs/library.a
