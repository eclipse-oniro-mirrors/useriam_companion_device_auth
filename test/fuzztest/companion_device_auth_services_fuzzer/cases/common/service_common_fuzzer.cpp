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
#include "service_common.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzDeviceKeyEquality(FuzzedDataProvider &fuzzData)
{
    DeviceKey key1 = GenerateFuzzDeviceKey(fuzzData);
    DeviceKey key2 = GenerateFuzzDeviceKey(fuzzData);
    bool equal = (key1 == key2);
    (void)equal;
}

static void FuzzDeviceKeyInequality(FuzzedDataProvider &fuzzData)
{
    DeviceKey key1 = GenerateFuzzDeviceKey(fuzzData);
    DeviceKey key2 = GenerateFuzzDeviceKey(fuzzData);
    bool notEqual = (key1 != key2);
    (void)notEqual;
}

static void FuzzDeviceKeyLessThan(FuzzedDataProvider &fuzzData)
{
    DeviceKey key1 = GenerateFuzzDeviceKey(fuzzData);
    DeviceKey key2 = GenerateFuzzDeviceKey(fuzzData);
    bool less = (key1 < key2);
    (void)less;
}

static void FuzzDeviceKeyGetDesc(FuzzedDataProvider &fuzzData)
{
    DeviceKey key = GenerateFuzzDeviceKey(fuzzData);
    auto desc = key.GetDesc();
    (void)desc;
}

static void FuzzDeviceStatusEquality(FuzzedDataProvider &fuzzData)
{
    DeviceStatus status1 = GenerateFuzzDeviceStatus(fuzzData);
    DeviceStatus status2 = GenerateFuzzDeviceStatus(fuzzData);
    bool equal = (status1 == status2);
    (void)equal;
}

static void FuzzDeviceKeyCopy(FuzzedDataProvider &fuzzData)
{
    DeviceKey key1 = GenerateFuzzDeviceKey(fuzzData);
    DeviceKey key2 = key1;
    bool equal = (key1 == key2);
    (void)equal;
}

static void FuzzDeviceKeyWithSameParams(FuzzedDataProvider &fuzzData)
{
    DeviceIdType deviceIdType = GenerateFuzzDeviceIdType(fuzzData);
    std::string deviceId = GenerateFuzzString(fuzzData, 64);
    UserId userId = fuzzData.ConsumeIntegral<UserId>();

    DeviceKey key1 { deviceIdType, deviceId, userId };
    DeviceKey key2 { deviceIdType, deviceId, userId };
    bool equal = (key1 == key2);
    (void)equal;
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzDeviceKeyEquality,
    FuzzDeviceKeyInequality,
    FuzzDeviceKeyLessThan,
    FuzzDeviceKeyGetDesc,
    FuzzDeviceStatusEquality,
    FuzzDeviceKeyCopy,
    FuzzDeviceKeyWithSameParams,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzServiceCommon(FuzzedDataProvider &fuzzData)
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
