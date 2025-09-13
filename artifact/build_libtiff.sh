#!/bin/bash

# build_libtiff.sh - Converted from Airflow DAG
# Description: 2025/09/07 ACSAC Artifact Evaluation
# Tags: project-ultimate-sanitizer, taint-tracking

set -e  # Exit on any error

# Get the script directory and set up paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR"

# Set up project directories
PROJECT_DIR="$ARTIFACT_DIR"
LLVM_DIR="$PROJECT_DIR/llvm-project"
TRY_CLANG_DIR="$PROJECT_DIR/try-clang"
MAGMA_DIR="$PROJECT_DIR/magma-v1.2"
EVALUATION_DIR="$PROJECT_DIR/evaluation"

# Set up build environment
CC="clang"
CXX="clang++"
CFLAGS="-w -g -fno-discard-value-names -DMAGMA_ENABLE_CANARIES -include $TRY_CLANG_DIR/canary.h -Wno-error=int-conversion"
CXXFLAGS="$CFLAGS"
LDFLAGS=""
LIBS="$MAGMA_DIR/fuzzers/vanilla/afl_driver.o"

# Target specific paths
target_libtiff="$MAGMA_DIR/targets/libtiff"
WORKDIR="$target_libtiff/repo"

# Function to execute docker operator equivalent
docker_operator() {
    local task_name="$1"
    local bash_command="$2"
    echo "Executing docker operator task: $task_name"
    echo "$bash_command" | ~/.cache/scalacli/local-repo/bin/scala-cli/scala-cli "$ARTIFACT_DIR/work-desk/exec.scala" -- polytracker
}

echo "Starting build_libtiff pipeline..."
echo "========================================"

# Task: fetch_sh
echo "Task: fetch_sh"
ls "$WORKDIR" || (TARGET="$target_libtiff" OUT="$target_libtiff" "$target_libtiff/fetch.sh")

# Task: build_vanilla_fuzzer (docker operator)
echo "Task: build_vanilla_fuzzer"
docker_operator "build_vanilla_fuzzer" "cd $WORKDIR && FUZZER=$MAGMA_DIR/fuzzers/vanilla OUT=\$FUZZER CXX=$CXX CXXFLAGS=\"\" $MAGMA_DIR/fuzzers/vanilla/build.polytracker.sh"

# Task: reset_tracee
echo "Task: reset_tracee"
git -C "$WORKDIR" reset --hard && git -C "$WORKDIR" clean -dfx

# Task: apply_patch
echo "Task: apply_patch"
cd "$WORKDIR" && TARGET="$target_libtiff" "$MAGMA_DIR/magma/apply_patches.sh"

# Task: manual_patch
echo "Task: manual_patch"
cd "$WORKDIR" && patch -p1 -i "$EVALUATION_DIR/libtiff/libtiff.no-va_arg.patch"

# Task: build_tracee_with_asan (docker operator)
echo "Task: build_tracee_with_asan"
docker_operator "build_tracee_with_asan" "CC=$CC CXX=$CXX CFLAGS=\"-g -fsanitize=address\" CXXFLAGS=\"-g -fsanitize=address\" LDFLAGS=$LDFLAGS LIBS=\"$LIBS\" TARGET=$target_libtiff OUT=$target_libtiff $target_libtiff/build.sh && cd $WORKDIR && cp -v build/tools/tiffcp ../tiffcp.asan"

# Task: make_clean
echo "Task: make_clean"
git -C "$WORKDIR" clean -dfx

# Task: build_tracee (docker operator)
echo "Task: build_tracee"
docker_operator "build_tracee" "CC=$CC CXX=$CXX CFLAGS=\"$CFLAGS\" CXXFLAGS=\"$CXXFLAGS\" LDFLAGS=$LDFLAGS LIBS=\"$LIBS\" TARGET=$target_libtiff OUT=$target_libtiff $target_libtiff/build.polytracker.sh"

echo "========================================"
echo "build_libtiff pipeline completed successfully!"