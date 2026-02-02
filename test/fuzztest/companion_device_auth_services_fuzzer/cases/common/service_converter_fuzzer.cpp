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
#include "service_converter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using ServiceConverterFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

namespace {
constexpr uint8_t CONVERTER_TYPE_PROTOCOL_ID = 0;
constexpr uint8_t CONVERTER_TYPE_CAPABILITY = 1;
constexpr uint8_t CONVERTER_TYPE_SECURE_PROTOCOL_ID = 2;
} // namespace

static void FuzzToUnderlying(FuzzedDataProvider &fuzzData)
{
    uint8_t converterType = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 2);
    uint32_t value = fuzzData.ConsumeIntegral<uint32_t>();

    switch (converterType) {
        case CONVERTER_TYPE_PROTOCOL_ID: {
            auto result = ProtocolIdConverter::ToUnderlying(static_cast<ProtocolId>(value));
            (void)result;
            break;
        }
        case CONVERTER_TYPE_CAPABILITY: {
            auto result = CapabilityConverter::ToUnderlying(static_cast<Capability>(value));
            (void)result;
            break;
        }
        case CONVERTER_TYPE_SECURE_PROTOCOL_ID: {
            auto result = SecureProtocolIdConverter::ToUnderlying(static_cast<SecureProtocolId>(value));
            (void)result;
            break;
        }
        default:
            break;
    }
}

static void FuzzFromUnderlying(FuzzedDataProvider &fuzzData)
{
    uint8_t converterType = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 2);
    uint16_t value = fuzzData.ConsumeIntegral<uint16_t>();

    switch (converterType) {
        case CONVERTER_TYPE_PROTOCOL_ID: {
            auto result = ProtocolIdConverter::FromUnderlying(value);
            (void)result;
            break;
        }
        case CONVERTER_TYPE_CAPABILITY: {
            auto result = CapabilityConverter::FromUnderlying(value);
            (void)result;
            break;
        }
        case CONVERTER_TYPE_SECURE_PROTOCOL_ID: {
            auto result = SecureProtocolIdConverter::FromUnderlying(value);
            (void)result;
            break;
        }
        default:
            break;
    }
}

static void FuzzToUnderlyingVec(FuzzedDataProvider &fuzzData)
{
    uint8_t converterType = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 2);
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_BUSINESS_IDS_COUNT);
    std::vector<uint16_t> inputVec;
    for (uint8_t i = 0; i < count; ++i) {
        inputVec.push_back(fuzzData.ConsumeIntegral<uint16_t>());
    }

    switch (converterType) {
        case CONVERTER_TYPE_PROTOCOL_ID: {
            std::vector<ProtocolId> enumVec;
            for (auto val : inputVec) {
                enumVec.push_back(static_cast<ProtocolId>(val));
            }
            auto result = ProtocolIdConverter::ToUnderlyingVec(enumVec);
            (void)result;
            break;
        }
        case CONVERTER_TYPE_CAPABILITY: {
            std::vector<Capability> enumVec;
            for (auto val : inputVec) {
                enumVec.push_back(static_cast<Capability>(val));
            }
            auto result = CapabilityConverter::ToUnderlyingVec(enumVec);
            (void)result;
            break;
        }
        case CONVERTER_TYPE_SECURE_PROTOCOL_ID: {
            std::vector<SecureProtocolId> enumVec;
            for (auto val : inputVec) {
                enumVec.push_back(static_cast<SecureProtocolId>(val));
            }
            auto result = SecureProtocolIdConverter::ToUnderlyingVec(enumVec);
            (void)result;
            break;
        }
        default:
            break;
    }
}

static void FuzzFromUnderlyingVec(FuzzedDataProvider &fuzzData)
{
    uint8_t converterType = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 2);
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_BUSINESS_IDS_COUNT);
    std::vector<uint16_t> underlyingVec;
    for (uint8_t i = 0; i < count; ++i) {
        underlyingVec.push_back(fuzzData.ConsumeIntegral<uint16_t>());
    }

    switch (converterType) {
        case CONVERTER_TYPE_PROTOCOL_ID: {
            auto result = ProtocolIdConverter::FromUnderlyingVec(underlyingVec);
            (void)result;
            break;
        }
        case CONVERTER_TYPE_CAPABILITY: {
            auto result = CapabilityConverter::FromUnderlyingVec(underlyingVec);
            (void)result;
            break;
        }
        case CONVERTER_TYPE_SECURE_PROTOCOL_ID: {
            auto result = SecureProtocolIdConverter::FromUnderlyingVec(underlyingVec);
            (void)result;
            break;
        }
        default:
            break;
    }
}

static const ServiceConverterFuzzFunction g_fuzzFuncs[] = {
    FuzzToUnderlying,
    FuzzFromUnderlying,
    FuzzToUnderlyingVec,
    FuzzFromUnderlyingVec,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(ServiceConverterFuzzFunction);

void FuzzServiceConverter(FuzzedDataProvider &fuzzData)
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

FUZZ_REGISTER(FuzzServiceConverter)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
