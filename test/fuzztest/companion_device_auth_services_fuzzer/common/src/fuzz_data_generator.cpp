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

namespace {
// Accessor kind per real CDA tag, mirroring the Encode/Decode call sites in services so that
// generated Attributes reach decode paths beyond the "attribute missing" early-return.
enum FuzzAttrType : uint8_t {
    FUZZ_ATTR_INT32,
    FUZZ_ATTR_UINT64,
    FUZZ_ATTR_UINT32,
    FUZZ_ATTR_UINT16,
    FUZZ_ATTR_BOOL,
    FUZZ_ATTR_STRING,
    FUZZ_ATTR_UINT8_ARRAY,
    FUZZ_ATTR_INT32_ARRAY,
    FUZZ_ATTR_UINT16_ARRAY,
    FUZZ_ATTR_TYPE_COUNT,
};

struct FuzzAttrSpec {
    Attributes::AttributeKey key;
    FuzzAttrType type;
};

const FuzzAttrSpec g_fuzzAttrSpecs[] = {
    { Attributes::ATTR_CDA_SA_HOST_USER_ID, FUZZ_ATTR_INT32 },
    { Attributes::ATTR_CDA_SA_COMPANION_USER_ID, FUZZ_ATTR_INT32 },
    { Attributes::ATTR_CDA_SA_RESULT, FUZZ_ATTR_INT32 },
    { Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, FUZZ_ATTR_INT32 },
    { Attributes::ATTR_CDA_SA_AUTH_INTENT, FUZZ_ATTR_INT32 },
    { Attributes::ATTR_CDA_SA_AUTH_SCENE, FUZZ_ATTR_INT32 },
    { Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, FUZZ_ATTR_STRING },
    { Attributes::ATTR_CDA_SA_REASON, FUZZ_ATTR_STRING },
    { Attributes::ATTR_CDA_SA_USER_NAME, FUZZ_ATTR_STRING },
    { Attributes::ATTR_CDA_SA_DEVICE_NAME, FUZZ_ATTR_STRING },
    { Attributes::ATTR_CDA_SA_MODEL, FUZZ_ATTR_STRING },
    { Attributes::ATTR_CDA_SA_CONNECTION_NAME, FUZZ_ATTR_STRING },
    { Attributes::ATTR_CDA_SA_NAVIGATION_BUTTON_TEXT, FUZZ_ATTR_STRING },
    { Attributes::ATTR_CDA_SA_WIDGET_TITLE, FUZZ_ATTR_STRING },
    { Attributes::ATTR_CDA_SA_EXTRA_INFO, FUZZ_ATTR_UINT8_ARRAY },
    { Attributes::ATTR_CDA_SA_SALT, FUZZ_ATTR_UINT8_ARRAY },
    { Attributes::ATTR_CDA_SA_SELECT_CONTEXT, FUZZ_ATTR_UINT8_ARRAY },
    { Attributes::ATTR_CDA_SA_CHALLENGE, FUZZ_ATTR_UINT64 },
    { Attributes::ATTR_CDA_SA_TEMPLATE_ID, FUZZ_ATTR_UINT64 },
    { Attributes::ATTR_CDA_SA_MSG_ACK, FUZZ_ATTR_BOOL },
    { Attributes::ATTR_CDA_SA_AUTH_STATE_MAINTAIN, FUZZ_ATTR_BOOL },
    { Attributes::ATTR_CDA_SA_MSG_TYPE, FUZZ_ATTR_UINT16 },
    { Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, FUZZ_ATTR_UINT16 },
    { Attributes::ATTR_CDA_SA_MSG_SEQ_NUM, FUZZ_ATTR_UINT32 },
    { Attributes::ATTR_CDA_SA_REMOTE_TOKEN_ID, FUZZ_ATTR_UINT32 },
    { Attributes::ATTR_CDA_SA_AUTH_TYPE, FUZZ_ATTR_INT32_ARRAY },
    { Attributes::ATTR_CDA_SA_BUSINESS_ID_LIST, FUZZ_ATTR_INT32_ARRAY },
    { Attributes::ATTR_CDA_SA_CAPABILITY_LIST, FUZZ_ATTR_UINT16_ARRAY },
    { Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, FUZZ_ATTR_UINT16_ARRAY },
};

const size_t FUZZ_ATTR_SPEC_COUNT = sizeof(g_fuzzAttrSpecs) / sizeof(g_fuzzAttrSpecs[0]);

// Weights out of FUZZ_ATTR_TOTAL_WEIGHT: mostly well-typed real tags (deep decode paths), plus
// type-confused real tags and unknown keys near the CDA range (malformed-peer cases).
constexpr uint8_t FUZZ_ATTR_TOTAL_WEIGHT = 10;
constexpr uint8_t FUZZ_UNKNOWN_TAG_WEIGHT = 1;
constexpr uint8_t FUZZ_WRONG_TYPE_WEIGHT = 1;
// Enum-sized values (ResultCode 0..19, DeviceIdType 0..2) so int32 attributes can hit SUCCESS
// and other defined values instead of only random garbage.
constexpr uint32_t FUZZ_ENUM_VALUE_MAX = 19;
constexpr size_t FUZZ_ATTR_VALUE_MAX_SIZE = 64;
constexpr size_t FUZZ_ATTR_ARRAY_MAX_COUNT = 8;
// Offset band around ATTR_CDA_SA_BEGIN for unknown-key generation: a few keys below the CDA
// range plus a wide span above it, so keys land outside the defined CDA tag set.
constexpr int32_t FUZZ_UNKNOWN_KEY_OFFSET_MIN = -16;
constexpr int32_t FUZZ_UNKNOWN_KEY_OFFSET_MAX = 256;

void FillFuzzAttribute(FuzzedDataProvider &fuzzData, Attributes &attrs, Attributes::AttributeKey key, FuzzAttrType type)
{
    switch (type) {
        case FUZZ_ATTR_INT32: {
            int32_t value = fuzzData.ConsumeBool()
                ? static_cast<int32_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_ENUM_VALUE_MAX))
                : fuzzData.ConsumeIntegral<int32_t>();
            attrs.SetInt32Value(key, value);
            break;
        }
        case FUZZ_ATTR_UINT64:
            attrs.SetUint64Value(key, fuzzData.ConsumeIntegral<uint64_t>());
            break;
        case FUZZ_ATTR_UINT32:
            attrs.SetUint32Value(key, fuzzData.ConsumeIntegral<uint32_t>());
            break;
        case FUZZ_ATTR_UINT16:
            attrs.SetUint16Value(key, fuzzData.ConsumeIntegral<uint16_t>());
            break;
        case FUZZ_ATTR_BOOL:
            attrs.SetBoolValue(key, fuzzData.ConsumeBool());
            break;
        case FUZZ_ATTR_STRING:
            attrs.SetStringValue(key, GenerateFuzzString(fuzzData));
            break;
        case FUZZ_ATTR_UINT8_ARRAY:
            attrs.SetUint8ArrayValue(key, GenerateFuzzVector<uint8_t>(fuzzData, FUZZ_ATTR_VALUE_MAX_SIZE));
            break;
        case FUZZ_ATTR_INT32_ARRAY:
            attrs.SetInt32ArrayValue(key, GenerateFuzzVector<int32_t>(fuzzData, FUZZ_ATTR_ARRAY_MAX_COUNT));
            break;
        case FUZZ_ATTR_UINT16_ARRAY:
            attrs.SetUint16ArrayValue(key, GenerateFuzzVector<uint16_t>(fuzzData, FUZZ_ATTR_ARRAY_MAX_COUNT));
            break;
        default:
            break;
    }
}
} // namespace

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
    size_t attrCount = fuzzData.ConsumeIntegralInRange<size_t>(0, maxAttributeCount);
    for (size_t i = 0; i < attrCount; ++i) {
        uint8_t selector = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_ATTR_TOTAL_WEIGHT - 1);
        Attributes::AttributeKey key;
        FuzzAttrType type;
        if (selector < FUZZ_UNKNOWN_TAG_WEIGHT) {
            key = static_cast<Attributes::AttributeKey>(static_cast<int32_t>(Attributes::ATTR_CDA_SA_BEGIN) +
                fuzzData.ConsumeIntegralInRange<int32_t>(FUZZ_UNKNOWN_KEY_OFFSET_MIN, FUZZ_UNKNOWN_KEY_OFFSET_MAX));
            type = static_cast<FuzzAttrType>(fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_ATTR_TYPE_COUNT - 1));
        } else {
            const FuzzAttrSpec &spec =
                g_fuzzAttrSpecs[fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_ATTR_SPEC_COUNT - 1)];
            key = spec.key;
            type = spec.type;
            if (selector < FUZZ_UNKNOWN_TAG_WEIGHT + FUZZ_WRONG_TYPE_WEIGHT) {
                type = static_cast<FuzzAttrType>(fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_ATTR_TYPE_COUNT - 1));
            }
        }
        FillFuzzAttribute(fuzzData, attrs, key, type);
    }
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
