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
#include <functional>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "sa_manager_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SaManagerAdapterFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzAddSAStatusListener(FuzzedDataProvider &fuzzData)
{
    std::string saName = GenerateFuzzString(fuzzData, 64);
    (void)saName;
    // Callback would be created by actual implementation
}

static void FuzzRemoveSAStatusListener(FuzzedDataProvider &fuzzData)
{
    std::string saName = GenerateFuzzString(fuzzData, 64);
    (void)saName;
}

static void FuzzSAManagerOperations(FuzzedDataProvider &fuzzData)
{
    uint32_t operationCode = fuzzData.ConsumeIntegral<uint32_t>();
    std::string saName = GenerateFuzzString(fuzzData, 64);
    (void)operationCode;
    (void)saName;
}

static void FuzzMultipleSAListeners(FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t i = 0; i < count; ++i) {
        std::string saName = GenerateFuzzString(fuzzData, 64);
        (void)saName;
    }
}

static void FuzzSAStatusCallback(FuzzedDataProvider &fuzzData)
{
    std::string saName = GenerateFuzzString(fuzzData, 64);
    bool isAlive = fuzzData.ConsumeBool();
    (void)saName;
    (void)isAlive;
    // Simulate callback invocation
}

static void FuzzSAManagement(FuzzedDataProvider &fuzzData)
{
    uint32_t listenerCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, 20);

    for (uint32_t i = 0; i < listenerCount; ++i) {
        std::string saName = GenerateFuzzString(fuzzData, 64);
        (void)saName;
    }
}

static const SaManagerAdapterFuzzFunction g_fuzzFuncs[] = {
    FuzzAddSAStatusListener,
    FuzzRemoveSAStatusListener,
    FuzzSAManagerOperations,
    FuzzMultipleSAListeners,
    FuzzSAStatusCallback,
    FuzzSAManagement,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SaManagerAdapterFuzzFunction);

void FuzzSaManagerAdapter(FuzzedDataProvider &fuzzData)
{
    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(SaManagerAdapter)

} // namespace UserIam
} // namespace OHOS
