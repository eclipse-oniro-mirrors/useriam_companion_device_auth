#!/usr/bin/env bash
# Copyright (c) 2025 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

usage() {
    cat <<EOF
Usage: $(basename "$0") [cov] [clean] [test <gtest_args>]
  (no args)          Build and run unit tests (Debug), reusing previous build output when present
  cov                Build with coverage flags, run unit tests, and emit coverage report when gcovr is available
  clean              Remove the existing build directory before configuring
  test <gtest_args>  Run tests with gtest arguments (e.g., test --gtest_filter=TestName.*)
EOF
}

ENABLE_COVERAGE=false
DO_CLEAN=false
TEST_MODE=false
GTEST_ARGS=()
# Set to false to disable parallel build (single-threaded), true to enable (default: true)
USE_PARALLEL="${USE_PARALLEL:-true}"

i=1
while [[ $i -le $# ]]; do
    arg="${!i}"
    case "${arg}" in
        cov)
            ENABLE_COVERAGE=true
            ((i++))
            ;;
        clean)
            DO_CLEAN=true
            ((i++))
            ;;
        test)
            TEST_MODE=true
            ((i++))
            # Collect all remaining arguments as gtest arguments
            while [[ $i -le $# ]]; do
                GTEST_ARGS+=("${!i}")
                ((i++))
            done
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

if ! command -v cmake >/dev/null 2>&1; then
    echo "cmake is required but not found in PATH." >&2
    exit 1
fi

detect_ohos_root() {
    local -a candidates=()
    local module_parent root_candidate env_var candidate

    if module_parent="$(cd "${MODULE_DIR}/.." && pwd)" &&
       root_candidate="$(cd "${module_parent}/.." && pwd)"; then
        candidates+=("${root_candidate}")
    fi

    for env_var in OHOS_ROOT OHOS_SOURCE_ROOT OHOS_PATH OHOS_BUILDROOT; do
        if [[ -n "${!env_var:-}" ]]; then
            candidates+=("${!env_var}")
        fi
    done

    if [[ -n "${HOME:-}" ]]; then
        candidates+=("${HOME}/code/OH/code")
    fi

    local -A seen=()
    for candidate in "${candidates[@]}"; do
        [[ -n "${candidate}" ]] || continue
        if [[ -n "${seen[${candidate}]+x}" ]]; then
            continue
        fi
        seen["${candidate}"]=1
        if [[ -d "${candidate}/base" ]]; then
            OHOS_ROOT="${candidate}"
            export OHOS_ROOT
            return 0
        fi
    done

    return 1
}

if [[ -z "${OHOS_ROOT:-}" ]]; then
    if detect_ohos_root; then
        echo "Detected OHOS_ROOT at ${OHOS_ROOT}"
    else
        echo "OHOS_ROOT environment variable must be set before running the unit tests." >&2
        exit 1
    fi
else
    echo "Using OHOS_ROOT from environment: ${OHOS_ROOT}"
fi

if [[ "${DO_CLEAN}" == true ]]; then
    echo "Cleaning existing build directory at ${BUILD_DIR}"
    rm -rf "${BUILD_DIR}"
fi

mkdir -p "${BUILD_DIR}"

CMAKE_ARGS=("-DCMAKE_BUILD_TYPE=Debug" "-DOHOS_ROOT=${OHOS_ROOT}")
if [[ "${ENABLE_COVERAGE}" == true ]]; then
    CMAKE_ARGS+=("-DCDA_ENABLE_COVERAGE=ON")
fi

if [[ -z "${CMAKE_GENERATOR:-}" ]] && command -v ninja >/dev/null 2>&1; then
    echo "Using Ninja generator for faster incremental builds"
    CMAKE_ARGS+=("-G" "Ninja")
fi

if command -v ccache >/dev/null 2>&1; then
    echo "Enabling ccache compiler launcher"
    export CCACHE_TEMPDIR="${BUILD_DIR}/ccache-tmp"
    mkdir -p "${CCACHE_TEMPDIR}"
    CMAKE_ARGS+=("-DCMAKE_C_COMPILER_LAUNCHER=ccache" "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache")
fi

parallel_jobs=""
if command -v nproc >/dev/null 2>&1; then
    parallel_jobs="$(nproc)"
elif command -v sysctl >/dev/null 2>&1; then
    parallel_jobs="$(sysctl -n hw.ncpu 2>/dev/null || true)"
fi

# Limit maximum parallel jobs to prevent memory exhaustion
MAX_PARALLEL_JOBS=4
if [[ -n "${parallel_jobs}" ]] && [[ "${parallel_jobs}" -gt "${MAX_PARALLEL_JOBS}" ]]; then
    echo "Detected ${parallel_jobs} CPU cores, but limiting to ${MAX_PARALLEL_JOBS} parallel jobs to prevent memory exhaustion"
    parallel_jobs="${MAX_PARALLEL_JOBS}"
fi

echo "Configuring unit tests at ${BUILD_DIR}"
cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" "${CMAKE_ARGS[@]}"

PARALLEL_FLAG=()
if [[ "${USE_PARALLEL}" == true ]] && [[ -n "${parallel_jobs}" ]]; then
    PARALLEL_FLAG=(--parallel "${parallel_jobs}" -j "${parallel_jobs}")
    echo "Building Companion Device Auth unit tests (using ${parallel_jobs} parallel jobs)"
else
    # Explicitly set to single-threaded
    PARALLEL_FLAG=(--parallel 1 -j 1)
    echo "Building Companion Device Auth unit tests (single-threaded)"
fi
cmake --build "${BUILD_DIR}" "${PARALLEL_FLAG[@]}"

# Note: All unit tests are compiled into a single executable: companion_device_auth_services_unittest
# This includes tests from attributes_test.cpp and device_status_manager_test.cpp
echo "Running unit tests"

if [[ "${TEST_MODE}" == true ]]; then
    # In test mode, pass gtest arguments directly to the test executable
    TEST_EXECUTABLE="${BUILD_DIR}/companion_device_auth_services_unittest"
    if [[ ! -f "${TEST_EXECUTABLE}" ]]; then
        echo "Error: Test executable not found at ${TEST_EXECUTABLE}" >&2
        exit 1
    fi
    echo "Running with gtest arguments: ${GTEST_ARGS[@]}"
    "${TEST_EXECUTABLE}" "${GTEST_ARGS[@]}"
else
    # In normal mode, use ctest to run tests
    CTEST_ARGS=(--test-dir "${BUILD_DIR}" --output-on-failure --output-xml "${BUILD_DIR}/companion_device_auth_services_unittest.xml")
    if [[ "${USE_PARALLEL}" == true ]] && [[ -n "${parallel_jobs}" ]]; then
        CTEST_ARGS+=(--parallel "${parallel_jobs}")
    fi
    ctest "${CTEST_ARGS[@]}"
fi

if [[ "${ENABLE_COVERAGE}" == true ]]; then
    COVERAGE_DIR="${BUILD_DIR}/coverage"
    mkdir -p "${COVERAGE_DIR}"
    if command -v gcovr >/dev/null 2>&1; then
        echo "Generating coverage report in ${COVERAGE_DIR}"
        if ! gcovr --root "${MODULE_DIR}" --object-directory "${BUILD_DIR}" \
            --html --html-details --output "${COVERAGE_DIR}/coverage.html" \
            --exclude-directories "${BUILD_DIR}/third_party"
        then
            echo "gcovr failed to generate HTML report" >&2
        fi
        if ! gcovr --root "${MODULE_DIR}" --object-directory "${BUILD_DIR}" \
            --xml -o "${COVERAGE_DIR}/coverage.xml" \
            --exclude-directories "${BUILD_DIR}/third_party" >/dev/null
        then
            echo "gcovr failed to generate XML report" >&2
        fi
    else
        echo "gcovr not found; coverage data (.gcda/.gcno) are available under ${BUILD_DIR}" >&2
    fi
fi
