/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdint>
#include <cstring>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    FuzzedDataProvider fuzzData(data, size);

    // Get all registered fuzz functions
    const auto &fuzzFunctions = FuzzRegistry::GetAllFunctions();
    size_t fuzzFunctionCount = FuzzRegistry::GetCount();

    // Read function index from fuzz data
    uint32_t functionIndex = fuzzData.ConsumeIntegral<uint32_t>();
    // Call the selected fuzz function if index is valid
    if (fuzzFunctionCount > 0 && functionIndex < fuzzFunctionCount) {
        fuzzFunctions[functionIndex](fuzzData);
    }

    return 0;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
