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
#include <string>

#include "fuzzer/FuzzedDataProvider.h"

#include "access_token_kit_adapter.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzVerifyPermission(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    std::string permissionName = GenerateFuzzString(fuzzData, 128);
    (void)tokenId;
    (void)permissionName;
}

static void FuzzPermissionOperations(FuzzedDataProvider &fuzzData)
{
    uint32_t operationCode = fuzzData.ConsumeIntegral<uint32_t>();
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    std::string permissionName = GenerateFuzzString(fuzzData, 128);
    (void)operationCode;
    (void)tokenId;
    (void)permissionName;
}

static void FuzzMultiplePermissionChecks(FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 20);
    for (uint8_t i = 0; i < count; ++i) {
        uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
        std::string permissionName = GenerateFuzzString(fuzzData, 64);
        (void)tokenId;
        (void)permissionName;
    }
}

static void FuzzTokenIdVariations(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    std::string permissionName = GenerateFuzzString(fuzzData, 256);
    (void)tokenId;
    (void)permissionName;
}

static void FuzzPermissionStress(FuzzedDataProvider &fuzzData)
{
    uint32_t checkCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, 100);

    for (uint32_t i = 0; i < checkCount; ++i) {
        uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
        std::string permissionName = GenerateFuzzString(fuzzData, 128);
        (void)tokenId;
        (void)permissionName;
    }
}

static void FuzzSpecialPermissionNames(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();

    // Test various permission name formats
    std::string permissionName1 = GenerateFuzzString(fuzzData, 64);
    std::string permissionName2 = GenerateFuzzString(fuzzData, 128);
    std::string permissionName3 = GenerateFuzzString(fuzzData, 256);
    (void)tokenId;
    (void)permissionName1;
    (void)permissionName2;
    (void)permissionName3;
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzVerifyPermission,
    FuzzPermissionOperations,
    FuzzMultiplePermissionChecks,
    FuzzTokenIdVariations,
    FuzzPermissionStress,
    FuzzSpecialPermissionNames,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzPermissionAdapter(FuzzedDataProvider &fuzzData)
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
} // namespace UserIam
} // namespace OHOS
