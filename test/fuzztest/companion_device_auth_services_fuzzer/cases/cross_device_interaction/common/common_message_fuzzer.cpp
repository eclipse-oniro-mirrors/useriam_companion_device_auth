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

#include "common_message.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
}

using CommonMessageFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzDecodeHostDeviceKey(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeHostDeviceKey(attr);
    (void)result;
}

static void FuzzDecodeCompanionDeviceKey(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeCompanionDeviceKey(attr);
    (void)result;
}

static void FuzzEncodeHostDeviceKey(FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey;
    deviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    deviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    deviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    deviceKey.deviceSubProfileId = fuzzData.ConsumeIntegral<int32_t>();
    Attributes attr;
    EncodeHostDeviceKey(deviceKey, attr);
}

static void FuzzEncodeCompanionDeviceKey(FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey;
    deviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    deviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    deviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    deviceKey.deviceSubProfileId = fuzzData.ConsumeIntegral<int32_t>();
    Attributes attr;
    EncodeCompanionDeviceKey(deviceKey, attr);
}

static const CommonMessageFuzzFunction FUZZ_FUNCS[] = {
    FuzzDecodeHostDeviceKey,
    FuzzDecodeCompanionDeviceKey,
    FuzzEncodeHostDeviceKey,
    FuzzEncodeCompanionDeviceKey,
};

/**
 * Fuzz sub-profile specific attribute keys for DecodeHostDeviceKey and DecodeCompanionDeviceKey.
 */
static void FuzzDecodeHostDeviceKeyWithSubProfile(FuzzedDataProvider &fuzzData)
{
    Attributes attr;
    attr.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, fuzzData.ConsumeIntegral<int32_t>());
    if (fuzzData.ConsumeBool()) {
        attr.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_SUB_PROFILE_ID, fuzzData.ConsumeIntegral<int32_t>());
    }
    attr.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, fuzzData.ConsumeIntegral<int32_t>());
    attr.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, GenerateFuzzString(fuzzData, TEST_VAL64));

    auto result = DecodeHostDeviceKey(attr);
    (void)result;
}

static void FuzzDecodeCompanionDeviceKeyWithSubProfile(FuzzedDataProvider &fuzzData)
{
    Attributes attr;
    attr.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, fuzzData.ConsumeIntegral<int32_t>());
    if (fuzzData.ConsumeBool()) {
        attr.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, fuzzData.ConsumeIntegral<int32_t>());
    }
    attr.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, fuzzData.ConsumeIntegral<int32_t>());
    attr.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, GenerateFuzzString(fuzzData, TEST_VAL64));

    auto result = DecodeCompanionDeviceKey(attr);
    (void)result;
}

static const CommonMessageFuzzFunction SUB_PROFILE_FUZZ_FUNCS[] = {
    FuzzDecodeHostDeviceKeyWithSubProfile,
    FuzzDecodeCompanionDeviceKeyWithSubProfile,
};

constexpr uint8_t NUM_SUB_PROFILE_FUZZ_OPS = sizeof(SUB_PROFILE_FUZZ_FUNCS) / sizeof(CommonMessageFuzzFunction);

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(FUZZ_FUNCS) / sizeof(CommonMessageFuzzFunction);

void FuzzCommonMessage(FuzzedDataProvider &fuzzData)
{
    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        FUZZ_FUNCS[i](fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        FUZZ_FUNCS[operation](fuzzData);
    }

    // Sub-profile specific fuzz loop
    for (size_t i = 0; i < NUM_SUB_PROFILE_FUZZ_OPS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        SUB_PROFILE_FUZZ_FUNCS[i](fuzzData);
        EnsureAllTaskExecuted();
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzCommonMessage)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
