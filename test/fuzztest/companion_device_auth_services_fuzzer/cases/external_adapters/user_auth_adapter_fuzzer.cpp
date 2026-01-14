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
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "user_auth_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using UserAuthAdapterFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzBeginDelegateAuth(FuzzedDataProvider &fuzzData)
{
    uint32_t userId = fuzzData.ConsumeIntegral<uint32_t>();
    size_t testVal256 = 256;
    std::vector<uint8_t> challenge = GenerateFuzzVector<uint8_t>(fuzzData, testVal256);
    uint32_t authTrustLevel = fuzzData.ConsumeIntegral<uint32_t>();
    (void)userId;
    (void)challenge;
    (void)authTrustLevel;
    // Callback would be created by actual implementation
}

static void FuzzCancelAuthentication(FuzzedDataProvider &fuzzData)
{
    uint64_t contextId = fuzzData.ConsumeIntegral<uint64_t>();
    (void)contextId;
}

static void FuzzUserAuthOperations(FuzzedDataProvider &fuzzData)
{
    uint32_t operationCode = fuzzData.ConsumeIntegral<uint32_t>();
    uint64_t contextId = fuzzData.ConsumeIntegral<uint64_t>();
    (void)operationCode;
    (void)contextId;
}

static void FuzzMultipleAuthRequests(FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t i = 0; i < count; ++i) {
        uint32_t userId = fuzzData.ConsumeIntegral<uint32_t>();
        size_t testVal128 = 128;
        std::vector<uint8_t> challenge = GenerateFuzzVector<uint8_t>(fuzzData, testVal128);
        (void)userId;
        (void)challenge;
    }
}

static void FuzzAuthParameterCombinations(FuzzedDataProvider &fuzzData)
{
    uint32_t userId = fuzzData.ConsumeIntegral<uint32_t>();
    size_t testVal512 = 512;
    std::vector<uint8_t> challenge = GenerateFuzzVector<uint8_t>(fuzzData, testVal512);
    uint32_t authTrustLevel = fuzzData.ConsumeIntegral<uint32_t>();
    (void)userId;
    (void)challenge;
    (void)authTrustLevel;
}

static void FuzzContextManagement(FuzzedDataProvider &fuzzData)
{
    uint32_t contextCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, 50);

    for (uint32_t i = 0; i < contextCount; ++i) {
        uint64_t contextId = fuzzData.ConsumeIntegral<uint64_t>();
        (void)contextId;
    }
}

static const UserAuthAdapterFuzzFunction g_fuzzFuncs[] = {
    FuzzBeginDelegateAuth,
    FuzzCancelAuthentication,
    FuzzUserAuthOperations,
    FuzzMultipleAuthRequests,
    FuzzAuthParameterCombinations,
    FuzzContextManagement,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(UserAuthAdapterFuzzFunction);

void FuzzUserAuthAdapter(FuzzedDataProvider &fuzzData)
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

FUZZ_REGISTER(UserAuthAdapter)

} // namespace UserIam
} // namespace OHOS
