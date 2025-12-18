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

#!/bin/bash
set -e

echo "Running cbindgen..."
mkdir -p gen

# Generate C header with cbindgen
cbindgen --config cbindgen.toml rust/entry/device_auth_ffi.rs -vv --output gen/cbindgen_device_auth_ffi.h

echo "cbindgen generation completed successfully!"
echo "Generated header: gen/cbindgen_device_auth_ffi.h"
