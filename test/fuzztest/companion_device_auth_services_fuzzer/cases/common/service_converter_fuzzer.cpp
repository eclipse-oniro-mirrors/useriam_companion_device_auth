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

static void FuzzCapabilityToUnderlying(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    Capability cap = Capability::DELEGATE_AUTH;
    auto underlying = EnumConverter<Capability, uint16_t>::ToUnderlying(cap);
    (void)underlying;
}

static void FuzzCapabilityFromUnderlying(FuzzedDataProvider &fuzzData)
{
    uint16_t underlyingValue = fuzzData.ConsumeIntegral<uint16_t>();
    auto cap = EnumConverter<Capability, uint16_t>::FromUnderlying(underlyingValue);
    (void)cap;
}

static void FuzzProtocolIdToUnderlying(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ProtocolId protocolId = ProtocolId::VERSION_1;
    auto underlying = EnumConverter<ProtocolId, uint16_t>::ToUnderlying(protocolId);
    (void)underlying;
}

static void FuzzProtocolIdFromUnderlying(FuzzedDataProvider &fuzzData)
{
    uint16_t underlyingValue = fuzzData.ConsumeIntegral<uint16_t>();
    auto protocolId = EnumConverter<ProtocolId, uint16_t>::FromUnderlying(underlyingValue);
    (void)protocolId;
}

static void FuzzCapabilityToUnderlyingVec(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::vector<Capability> capVec = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH };
    auto underlyingVec = EnumConverter<Capability, uint16_t>::ToUnderlyingVec(capVec);
    (void)underlyingVec;
}

static void FuzzCapabilityToUnderlyingVecSingle(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::vector<Capability> capVec = { Capability::DELEGATE_AUTH };
    auto underlyingVec = EnumConverter<Capability, uint16_t>::ToUnderlyingVec(capVec);
    (void)underlyingVec;
}

static void FuzzCapabilityToUnderlyingVecEmpty(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::vector<Capability> capVec;
    auto underlyingVec = EnumConverter<Capability, uint16_t>::ToUnderlyingVec(capVec);
    (void)underlyingVec;
}

static const ServiceConverterFuzzFunction g_fuzzFuncs[] = {
    FuzzCapabilityToUnderlying,
    FuzzCapabilityFromUnderlying,
    FuzzProtocolIdToUnderlying,
    FuzzProtocolIdFromUnderlying,
    FuzzCapabilityToUnderlyingVec,
    FuzzCapabilityToUnderlyingVecSingle,
    FuzzCapabilityToUnderlyingVecEmpty,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(ServiceConverterFuzzFunction);

void FuzzServiceConverter(FuzzedDataProvider &fuzzData)
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

FUZZ_REGISTER(ServiceConverter)

} // namespace UserIam
} // namespace OHOS
