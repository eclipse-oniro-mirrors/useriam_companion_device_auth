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
#include "subscription_util.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SubscriptionUtilFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzConvertToIpcDeviceStatus(FuzzedDataProvider &fuzzData)
{
    DeviceStatus status = GenerateFuzzDeviceStatus(fuzzData);
    auto ipcStatus = ConvertToIpcDeviceStatus(status);
    (void)ipcStatus;
}

static void FuzzConvertToIpcDeviceStatusWithEmptyFields(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    DeviceStatus status;
    auto ipcStatus = ConvertToIpcDeviceStatus(status);
    (void)ipcStatus;
}

static void FuzzConvertToIpcDeviceStatusWithLargeDeviceId(FuzzedDataProvider &fuzzData)
{
    DeviceStatus status = GenerateFuzzDeviceStatus(fuzzData);
    status.deviceKey.deviceId = GenerateFuzzString(fuzzData, FUZZ_MAX_STRING_SIZE);
    auto ipcStatus = ConvertToIpcDeviceStatus(status);
    (void)ipcStatus;
}

static void FuzzConvertToIpcTemplateStatus(FuzzedDataProvider &fuzzData)
{
    CompanionStatus companionStatus = GenerateFuzzCompanionStatus(fuzzData);
    std::optional<int64_t> manageSubscribeTime = std::make_optional(fuzzData.ConsumeIntegral<int64_t>());
    auto ipcStatus = ConvertToIpcTemplateStatus(companionStatus, manageSubscribeTime);
    (void)ipcStatus;
}

static void FuzzConvertToIpcTemplateStatusWithoutSubscribeTime(FuzzedDataProvider &fuzzData)
{
    CompanionStatus companionStatus = GenerateFuzzCompanionStatus(fuzzData);
    std::optional<int64_t> manageSubscribeTime = std::nullopt;
    auto ipcStatus = ConvertToIpcTemplateStatus(companionStatus, manageSubscribeTime);
    (void)ipcStatus;
}

static void FuzzConvertToIpcTemplateStatusWithEmptyStatus(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    CompanionStatus companionStatus;
    std::optional<int64_t> manageSubscribeTime = std::nullopt;
    auto ipcStatus = ConvertToIpcTemplateStatus(companionStatus, manageSubscribeTime);
    (void)ipcStatus;
}

static const SubscriptionUtilFuzzFunction g_fuzzFuncs[] = {
    FuzzConvertToIpcDeviceStatus,
    FuzzConvertToIpcDeviceStatusWithEmptyFields,
    FuzzConvertToIpcDeviceStatusWithLargeDeviceId,
    FuzzConvertToIpcTemplateStatus,
    FuzzConvertToIpcTemplateStatusWithoutSubscribeTime,
    FuzzConvertToIpcTemplateStatusWithEmptyStatus,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SubscriptionUtilFuzzFunction);

void FuzzSubscriptionUtil(FuzzedDataProvider &fuzzData)
{
    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzSubscriptionUtil)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
