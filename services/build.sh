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
BUILD_DIR="${SCRIPT_DIR}/build"

usage() {
    cat <<EOF
Usage: $(basename "$0") [debug]
  debug   Build Companion Device Auth services in Debug mode

Without arguments the script performs a Release build. Unit tests and coverage
are handled by test/unittest/test.sh.
EOF
}

BUILD_TYPE="Release"

for arg in "$@"; do
    case "${arg}" in
        debug)
            BUILD_TYPE="Debug"
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

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

echo "Configuring build directory at ${BUILD_DIR}"
cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"

PARALLEL_FLAG=()
if command -v nproc >/dev/null 2>&1; then
    PARALLEL_FLAG=(--parallel "$(nproc)")
fi

echo "Building Companion Device Auth services"
cmake --build "${BUILD_DIR}" "${PARALLEL_FLAG[@]}"
