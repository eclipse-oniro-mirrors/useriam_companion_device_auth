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

#ifndef COMPANION_DEVICE_AUTH_FUZZ_DATA_GENERATOR_H
#define COMPANION_DEVICE_AUTH_FUZZ_DATA_GENERATOR_H

#include <cstdint>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "cda_attributes.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr uint32_t FUZZ_MAX_STRING_SIZE = 256;

// Template function for generating a vector of fuzz data
template <typename T>
std::vector<T> GenerateFuzzVector(FuzzedDataProvider &fuzzData, size_t maxSize)
{
    std::vector<T> result;
    size_t size = fuzzData.ConsumeIntegralInRange<size_t>(0, maxSize);
    for (size_t i = 0; i < size; ++i) {
        result.push_back(fuzzData.ConsumeIntegral<T>());
    }
    return result;
}

DeviceKey GenerateFuzzDeviceKey(FuzzedDataProvider &fuzzData);
DeviceStatus GenerateFuzzDeviceStatus(FuzzedDataProvider &fuzzData);
std::vector<DeviceStatus> GenerateFuzzDeviceStatusList(FuzzedDataProvider &fuzzData, uint8_t maxCount = 5);
PersistedHostBindingStatus GenerateFuzzPersistedHostBindingStatus(FuzzedDataProvider &fuzzData);
HostBindingStatus GenerateFuzzHostBindingStatus(FuzzedDataProvider &fuzzData);
CompanionStatus GenerateFuzzCompanionStatus(FuzzedDataProvider &fuzzData);

void GenerateFuzzCapabilities(FuzzedDataProvider &fuzzData, std::vector<Capability> &capabilities,
    uint8_t maxCount = 2);
void GenerateFuzzBusinessIds(FuzzedDataProvider &fuzzData, std::vector<int32_t> &businessIds, uint8_t maxCount = 3);
void GenerateFuzzProtocols(FuzzedDataProvider &fuzzData, std::vector<ProtocolId> &protocols, uint8_t maxCount = 2);
void GenerateFuzzSecureProtocols(FuzzedDataProvider &fuzzData, std::vector<SecureProtocolId> &secureProtocols,
    uint8_t maxCount = 3);
void FillDeviceStatusVector(FuzzedDataProvider &fuzzData, std::vector<DeviceStatus> &statuses, size_t maxCount = 100);
void FillDeviceKeyVector(FuzzedDataProvider &fuzzData, std::vector<DeviceKey> &deviceKeys, size_t maxCount = 100);

std::string GenerateFuzzString(FuzzedDataProvider &fuzzData, uint32_t maxSize = FUZZ_MAX_STRING_SIZE);
std::string GenerateRandomString(FuzzedDataProvider &fuzzData, uint32_t maxSize = 100);
ChannelId GenerateFuzzChannelId(FuzzedDataProvider &fuzzData);
ProtocolId GenerateFuzzProtocolId(FuzzedDataProvider &fuzzData);
SecureProtocolId GenerateFuzzSecureProtocolId(FuzzedDataProvider &fuzzData);
Capability GenerateFuzzCapability(FuzzedDataProvider &fuzzData);
DeviceIdType GenerateFuzzDeviceIdType(FuzzedDataProvider &fuzzData);
ResultCode GenerateFuzzResultCode(FuzzedDataProvider &fuzzData);
bool GenerateFuzzBool(FuzzedDataProvider &fuzzData);
Attributes GenerateFuzzAttributes(FuzzedDataProvider &fuzzData, size_t maxAttributeCount = 50);

void EnsureAllTaskExecuted();

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FUZZ_DATA_GENERATOR_H
