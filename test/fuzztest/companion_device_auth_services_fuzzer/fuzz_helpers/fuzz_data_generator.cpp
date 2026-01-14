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

#include "fuzz_data_generator.h"

#include "relative_timer.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::string GenerateFuzzString(FuzzedDataProvider &fuzzData, uint32_t maxSize)
{
    return fuzzData.ConsumeRandomLengthString(maxSize);
}

std::string GenerateRandomString(FuzzedDataProvider &fuzzData, uint32_t maxSize)
{
    return fuzzData.ConsumeRandomLengthString(maxSize);
}

ResultCode GenerateFuzzResultCode(FuzzedDataProvider &fuzzData)
{
    return static_cast<ResultCode>(fuzzData.ConsumeIntegral<uint32_t>());
}

bool GenerateFuzzBool(FuzzedDataProvider &fuzzData)
{
    return fuzzData.ConsumeIntegral<uint32_t>() > 0;
}

Attributes GenerateFuzzAttributes(FuzzedDataProvider &fuzzData, size_t maxAttributeCount)
{
    Attributes attrs;
    (void)fuzzData;
    (void)maxAttributeCount;
    return attrs;
}

void FillDeviceStatusVector(FuzzedDataProvider &fuzzData, std::vector<DeviceStatus> &statuses, size_t maxCount)
{
    size_t count = fuzzData.ConsumeIntegralInRange<size_t>(0, maxCount);
    statuses.clear();
    for (size_t i = 0; i < count; ++i) {
        statuses.push_back(GenerateFuzzDeviceStatus(fuzzData));
    }
}

void FillDeviceKeyVector(FuzzedDataProvider &fuzzData, std::vector<DeviceKey> &deviceKeys, size_t maxCount)
{
    size_t count = fuzzData.ConsumeIntegralInRange<size_t>(0, maxCount);
    deviceKeys.clear();
    for (size_t i = 0; i < count; ++i) {
        deviceKeys.push_back(GenerateFuzzDeviceKey(fuzzData));
    }
}

DeviceIdType GenerateFuzzDeviceIdType(FuzzedDataProvider &fuzzData)
{
    int32_t leftRange = 0;
    int32_t rightRange = 2;
    return static_cast<DeviceIdType>(fuzzData.ConsumeIntegralInRange<int32_t>(leftRange, rightRange));
}

ChannelId GenerateFuzzChannelId(FuzzedDataProvider &fuzzData)
{
    int32_t leftRange = 0;
    int32_t rightRange = 3;
    return static_cast<ChannelId>(fuzzData.ConsumeIntegralInRange<int32_t>(leftRange, rightRange));
}

ProtocolId GenerateFuzzProtocolId(FuzzedDataProvider &fuzzData)
{
    int32_t leftRange = 0;
    int32_t rightRange = 1;
    return static_cast<ProtocolId>(fuzzData.ConsumeIntegralInRange<uint16_t>(leftRange, rightRange));
}

SecureProtocolId GenerateFuzzSecureProtocolId(FuzzedDataProvider &fuzzData)
{
    int32_t leftRange = 0;
    int32_t rightRange = 3;
    return static_cast<SecureProtocolId>(fuzzData.ConsumeIntegralInRange<uint16_t>(leftRange, rightRange));
}

Capability GenerateFuzzCapability(FuzzedDataProvider &fuzzData)
{
    int32_t leftRange = 1;
    int32_t rightRange = 2;
    return static_cast<Capability>(fuzzData.ConsumeIntegralInRange<uint16_t>(leftRange, rightRange));
}

DeviceKey GenerateFuzzDeviceKey(FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey;
    deviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    deviceKey.deviceId = GenerateFuzzString(fuzzData, FUZZ_MAX_STRING_SIZE);
    deviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    return deviceKey;
}

void GenerateFuzzCapabilities(FuzzedDataProvider &fuzzData, std::vector<Capability> &capabilities, uint8_t maxCount)
{
    uint8_t capCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, maxCount);
    for (uint8_t i = 0; i < capCount; ++i) {
        capabilities.push_back(GenerateFuzzCapability(fuzzData));
    }
}

void GenerateFuzzBusinessIds(FuzzedDataProvider &fuzzData, std::vector<BusinessId> &businessIds, uint8_t maxCount)
{
    uint8_t bizIdCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, maxCount);
    for (uint8_t i = 0; i < bizIdCount; ++i) {
        businessIds.push_back(static_cast<BusinessId>(fuzzData.ConsumeIntegral<int32_t>()));
    }
}

void GenerateFuzzProtocols(FuzzedDataProvider &fuzzData, std::vector<ProtocolId> &protocols, uint8_t maxCount)
{
    uint8_t protocolCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, maxCount);
    for (uint8_t i = 0; i < protocolCount; ++i) {
        protocols.push_back(GenerateFuzzProtocolId(fuzzData));
    }
}

void GenerateFuzzSecureProtocols(FuzzedDataProvider &fuzzData, std::vector<SecureProtocolId> &secureProtocols,
    uint8_t maxCount)
{
    uint8_t secureProtocolCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, maxCount);
    for (uint8_t i = 0; i < secureProtocolCount; ++i) {
        secureProtocols.push_back(GenerateFuzzSecureProtocolId(fuzzData));
    }
}

DeviceStatus GenerateFuzzDeviceStatus(FuzzedDataProvider &fuzzData)
{
    DeviceStatus status;
    status.deviceKey = GenerateFuzzDeviceKey(fuzzData);
    status.channelId = GenerateFuzzChannelId(fuzzData);
    status.deviceModelInfo = GenerateFuzzString(fuzzData, FUZZ_MAX_STRING_SIZE);
    status.deviceUserName = GenerateFuzzString(fuzzData, FUZZ_MAX_STRING_SIZE);
    status.deviceName = GenerateFuzzString(fuzzData, FUZZ_MAX_STRING_SIZE);
    status.protocolId = GenerateFuzzProtocolId(fuzzData);
    status.secureProtocolId = GenerateFuzzSecureProtocolId(fuzzData);
    status.isOnline = fuzzData.ConsumeBool();
    status.isAuthMaintainActive = fuzzData.ConsumeBool();

    const uint8_t capabilitiesVal = 2;
    const uint8_t supportedBusinessIdsVal = 3;
    GenerateFuzzCapabilities(fuzzData, status.capabilities, capabilitiesVal);
    GenerateFuzzBusinessIds(fuzzData, status.supportedBusinessIds, supportedBusinessIdsVal);

    return status;
}

std::vector<DeviceStatus> GenerateFuzzDeviceStatusList(FuzzedDataProvider &fuzzData, uint8_t maxCount)
{
    std::vector<DeviceStatus> statusList;
    uint8_t statusCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, maxCount);
    for (uint8_t i = 0; i < statusCount; ++i) {
        statusList.push_back(GenerateFuzzDeviceStatus(fuzzData));
    }
    return statusList;
}

PersistedHostBindingStatus GenerateFuzzPersistedHostBindingStatus(FuzzedDataProvider &fuzzData)
{
    PersistedHostBindingStatus status;
    status.bindingId = fuzzData.ConsumeIntegral<uint32_t>();
    status.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    status.hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    status.isTokenValid = fuzzData.ConsumeBool();
    return status;
}

HostBindingStatus GenerateFuzzHostBindingStatus(FuzzedDataProvider &fuzzData)
{
    HostBindingStatus status;
    status.bindingId = fuzzData.ConsumeIntegral<uint32_t>();
    status.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    status.hostDeviceStatus = GenerateFuzzDeviceStatus(fuzzData);
    status.isTokenValid = fuzzData.ConsumeBool();
    status.localAuthMaintainActive = fuzzData.ConsumeBool();
    return status;
}

CompanionStatus GenerateFuzzCompanionStatus(FuzzedDataProvider &fuzzData)
{
    CompanionStatus status;
    status.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    status.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
    status.companionDeviceStatus = GenerateFuzzDeviceStatus(fuzzData);
    status.isValid = fuzzData.ConsumeBool();
    status.addedTime = fuzzData.ConsumeIntegral<int64_t>();
    status.lastCheckTime = fuzzData.ConsumeIntegral<int64_t>();

    // Generate enabledBusinessIds
    uint8_t businessIdCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t i = 0; i < businessIdCount; ++i) {
        status.enabledBusinessIds.push_back(static_cast<BusinessId>(fuzzData.ConsumeIntegral<int32_t>()));
    }

    return status;
}

void EnsureAllTaskExecuted()
{
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
