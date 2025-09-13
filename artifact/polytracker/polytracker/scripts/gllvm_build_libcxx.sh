#!/usr/bin/env bash

mkdir build
cd build || exit

SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# shellcheck disable=SC2034
POLYROOT="$SCRIPTPATH/../../build/share/polytracker/"

export CC="gclang -Xclang -disable-O0-optnone"
echo "$CC"
export CXX="gclang++ -Xclang -disable-O0-optnone"
echo "$CXX"

cmake -G Ninja \
	-DCMAKE_C_FLAGS="-fPIC" \
	-DCMAKE_CXX_FLAGS="-fPIC" \
	-DCMAKE_INSTALL_PREFIX=/cxx_track/ \
	-DLLVM_ENABLE_PROJECTS="libcxx;libcxxabi;libunwind" \
	-DLLVM_TARGETS_TO_BUILD="X86" \
	-DLIBCXX_ENABLE_SHARED=NO \
	-DLIBCXX_ENABLE_STATIC=YES \
	-DLIBCXX_CXX_ABI=libcxxabi \
	../llvm-project/llvm/

ninja cxx cxxabi unwind
