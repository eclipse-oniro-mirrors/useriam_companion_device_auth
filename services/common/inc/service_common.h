/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMPANION_DEVICE_AUTH_SERVICE_COMMON_H
#define COMPANION_DEVICE_AUTH_SERVICE_COMMON_H

#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "iam_para2str.h"

#include "common_defines.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FwkResultCallback = std::function<void(ResultCode result, const std::vector<uint8_t> &extraInfo)>;
using ResultCodeCallback = std::function<void(ResultCode result)>;

using RequestId = uint32_t;
using TemplateId = uint64_t;
using ScheduleId = uint64_t;
using UserId = int32_t;
using BindingId = uint32_t;
using SubscribeId = uint64_t;
using Atl = int32_t;
using SystemTimeMs = uint64_t;
using SteadyTimeMs = uint64_t;

enum class ChannelId : int32_t {
    INVALID = 0,
    SOFTBUS = 1,
};

enum class Capability : uint16_t {
    INVALID = 0,
    DELEGATE_AUTH = 1,
    TOKEN_AUTH = 2,
    OBTAIN_TOKEN = 3,
};

enum class ProtocolId : uint16_t {
    INVALID = 0,
    VERSION_1 = 1,
};

enum class SecureProtocolId : uint16_t {
    INVALID = 0,
    DEFAULT = 1,
};

constexpr int32_t INVALID_USER_ID = -1;

enum class MessageType : uint16_t {
    // Invalid
    INVALID = 0x0000,
    // Device status sync (0x01xx)
    SYNC_DEVICE_STATUS = 0x0101,
    REQUEST_DEVICE_RESYNC = 0x0102,

    // Bind companion device (0x03xx)
    INIT_KEY_NEGOTIATION = 0x0301,
    BEGIN_ADD_HOST_BINDING = 0x0302,
    END_ADD_HOST_BINDING = 0x0303,

    // Unbind companion device (0x04xx)
    REMOVE_HOST_BINDING = 0x0401,

    // Delegate auth (0x05xx)
    START_DELEGATE_AUTH = 0x0501,
    SEND_DELEGATE_AUTH_RESULT = 0x0502,

    // Issue token (0x06xx)
    PRE_ISSUE_TOKEN = 0x0601,
    ISSUE_TOKEN = 0x0602,

    // Token auth (0x07xx)
    TOKEN_AUTH = 0x0701,

    // Revoke token (0x08xx)
    COMPANION_REVOKE_TOKEN = 0x0801,

    // Companion obtain token (0x0Axx)
    PRE_OBTAIN_TOKEN = 0x0A01,
    OBTAIN_TOKEN = 0x0A02,

    // Keep alive (0x0Bxx)
    KEEP_ALIVE = 0x0B01,

    // Disconnect (0x0Cxx - auxiliary messages)
    DISCONNECT = 0x0C01,

    // Request abort notification (0x0Dxx - auxiliary messages)
    REQUEST_ABORTED = 0x0D01,
};

enum class DeviceType : int32_t {
    INVALID = 0,
    PHONE = 1,
    PAD = 2,
    TWO_IN_ONE = 3,
    PC = 4,
    UNKNOWN = 5,
};

class DeviceKey {
public:
    bool operator==(const DeviceKey &other) const
    {
        return idType == other.idType && deviceId == other.deviceId && deviceUserId == other.deviceUserId;
    }

    bool operator!=(const DeviceKey &other) const
    {
        return !(*this == other);
    }

    bool operator<(const DeviceKey &other) const
    {
        if (idType != other.idType) {
            return idType < other.idType;
        }
        if (deviceId != other.deviceId) {
            return deviceId < other.deviceId;
        }
        return deviceUserId < other.deviceUserId;
    }

    std::string GetDesc() const
    {
        std::ostringstream oss;
        oss << "(t:" << static_cast<int32_t>(idType) << ", id: " << GetMaskedString(deviceId) << ""
            << ", user:" << deviceUserId << ")";
        return oss.str();
    }

    static std::string GetVectorDesc(const std::vector<DeviceKey> &devices)
    {
        std::ostringstream oss;
        oss << "[";
        for (size_t i = 0; i < devices.size(); ++i) {
            if (i > 0) {
                oss << ", ";
            }
            oss << "[" << i << "]" << devices[i].GetDesc();
        }
        oss << "]";
        return oss.str();
    }

    DeviceIdType idType { DeviceIdType::UNKNOWN };
    std::string deviceId {};
    UserId deviceUserId { INVALID_USER_ID };
};

class DeviceStatus {
public:
    bool operator==(const DeviceStatus &other) const
    {
        return deviceKey == other.deviceKey && channelId == other.channelId &&
            deviceModelInfo == other.deviceModelInfo && deviceUserName == other.deviceUserName &&
            deviceName == other.deviceName && protocolId == other.protocolId &&
            secureProtocolId == other.secureProtocolId && capabilities == other.capabilities &&
            supportedBusinessIds == other.supportedBusinessIds && isOnline == other.isOnline &&
            isAuthMaintainActive == other.isAuthMaintainActive && deviceType == other.deviceType &&
            atlRevokeDelayMs == other.atlRevokeDelayMs && refreshToken == other.refreshToken;
    }

    DeviceKey deviceKey {};
    ChannelId channelId { ChannelId::INVALID };
    std::string deviceModelInfo {};
    std::string deviceUserName {};
    std::string deviceName {};
    ProtocolId protocolId { ProtocolId::INVALID };
    SecureProtocolId secureProtocolId { SecureProtocolId::INVALID };
    std::vector<Capability> capabilities {};
    std::vector<BusinessId> supportedBusinessIds {};
    bool isOnline { false };
    bool isAuthMaintainActive { false };
    DeviceType deviceType { DeviceType::INVALID };
    std::optional<uint32_t> atlRevokeDelayMs;
    bool refreshToken { false };
};

struct LocalDeviceProfile {
    std::vector<ProtocolId> protocols;
    std::vector<SecureProtocolId> hostSecureProtocols;
    SecureProtocolId companionSecureProtocolId { SecureProtocolId::INVALID };
    std::vector<Capability> hostCapabilities;
    std::vector<Capability> companionCapabilities;
    std::vector<BusinessId> hostSupportedBusinessIds;
    std::vector<BusinessId> companionSupportedBusinessIds;
    std::vector<ProtocolId> protocolPriorityList;
    bool hostBindingRevokeTokenOnInactive { false };
};

struct LocalDeviceAuthState {
    bool isAuthMaintainActive { false };
};

struct PersistedCompanionStatus {
    TemplateId templateId { 0 };
    UserId hostUserId { INVALID_USER_ID };
    DeviceKey companionDeviceKey {};
    bool isValid { false };
    std::vector<BusinessId> enabledBusinessIds {};
    int64_t addedTime { 0 };
    std::string deviceModelInfo {};
    std::string deviceUserName {};
    std::string deviceName {};
    DeviceType deviceType { DeviceType::INVALID };
};

struct CompanionStatus {
    CompanionStatus() = default;

    CompanionStatus &FromPersisted(const PersistedCompanionStatus &persistedStatus)
    {
        templateId = persistedStatus.templateId;
        hostUserId = persistedStatus.hostUserId;
        isValid = persistedStatus.isValid;
        enabledBusinessIds = persistedStatus.enabledBusinessIds;
        addedTime = persistedStatus.addedTime;
        companionDeviceStatus.deviceKey = persistedStatus.companionDeviceKey;
        companionDeviceStatus.deviceModelInfo = persistedStatus.deviceModelInfo;
        companionDeviceStatus.deviceUserName = persistedStatus.deviceUserName;
        companionDeviceStatus.deviceName = persistedStatus.deviceName;
        companionDeviceStatus.deviceType = persistedStatus.deviceType;
        tokenAuthAtl = std::nullopt;
        return *this;
    }

    PersistedCompanionStatus ToPersisted() const
    {
        PersistedCompanionStatus persistedStatus;
        persistedStatus.templateId = templateId;
        persistedStatus.hostUserId = hostUserId;
        persistedStatus.isValid = isValid;
        persistedStatus.enabledBusinessIds = enabledBusinessIds;
        persistedStatus.addedTime = addedTime;
        persistedStatus.companionDeviceKey = companionDeviceStatus.deviceKey;
        persistedStatus.deviceModelInfo = companionDeviceStatus.deviceModelInfo;
        persistedStatus.deviceUserName = companionDeviceStatus.deviceUserName;
        persistedStatus.deviceName = companionDeviceStatus.deviceName;
        persistedStatus.deviceType = companionDeviceStatus.deviceType;
        return persistedStatus;
    }

    std::string GetDesc() const
    {
        std::ostringstream oss;
        oss << "(T:" << GET_MASKED_NUM_STRING(templateId) << ", D:" << companionDeviceStatus.deviceKey.GetDesc() << ")";
        return oss.str();
    }

    TemplateId templateId { 0 };
    UserId hostUserId { INVALID_USER_ID };
    DeviceStatus companionDeviceStatus {};
    bool isValid { true };
    std::optional<Atl> tokenAuthAtl { std::nullopt };
    std::vector<BusinessId> enabledBusinessIds {};
    int64_t addedTime { 0 };
    uint64_t lastCheckTime { 0 };
};

struct HostBindingStatus {
    BindingId bindingId { 0 };
    UserId companionUserId { INVALID_USER_ID };
    DeviceStatus hostDeviceStatus {};
    bool isTokenValid { false };
    bool localAuthMaintainActive { false };
};

struct PersistedHostBindingStatus {
    BindingId bindingId { 0 };
    UserId companionUserId { INVALID_USER_ID };
    DeviceKey hostDeviceKey {};
    bool isTokenValid { false };
};

struct SecureExecutorInfo {
    int32_t esl { 0 };
    uint32_t maxTemplateAcl { 0 };
    std::vector<uint8_t> publicKey {};
};

struct SyncDeviceStatus {
    bool needSync { false };
    std::vector<ProtocolId> protocolIdList;
    std::vector<Capability> capabilityList;
    std::vector<BusinessId> businessIdList;
    SecureProtocolId secureProtocolId;
    std::string deviceUserName {};
    int32_t deviceUserId { INVALID_USER_ID };
    std::string deviceName {};
};

struct DeviceCapabilityInfo {
    std::vector<BusinessId> hostSupportedBusinessIds;
    std::vector<Capability> hostLocalCapabilities;
    std::vector<BusinessId> companionSupportedBusinessIds;
    std::vector<Capability> companionLocalCapabilities;
};

constexpr uint32_t DEFAULT_REQUEST_TIMEOUT_MS = 60 * 1000;           // 60 seconds
constexpr uint32_t TOKEN_TIMEOUT_MS = 4 * 60 * 60 * 1000;            // 4 hours
constexpr uint32_t TOKEN_ENROLL_NOT_WORN_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
constexpr uint32_t IDM_ADD_TEMPLATE_TIMEOUT_MS = 30 * 1000;          // 30 seconds
constexpr uint64_t CONNECTION_IDLE_TIMEOUT_MS = 10 * 1000;           // 10 seconds
constexpr uint32_t CONNECTION_IDLE_MONITOR_INTERVAL_MS = 10 * 1000;  // 10 seconds
constexpr uint32_t MAX_SYNC_WAIT_TIME_SEC = 2;                       // 2 second
constexpr uint32_t MAX_ON_START_WAIT_TIME_SEC = UINT32_MAX;
constexpr uint32_t SET_PARAM_DELAY_MS = 100; // 100ms
constexpr size_t MAX_MESSAGE_SIZE = 20000;
constexpr size_t MAX_ENABLED_BUSINESS_IDS = 64;
constexpr int32_t MS_PER_SEC = 1000;
constexpr int32_t NS_PER_MS = 1000 * 1000;
constexpr int32_t BYTE_NUM_4 = 4;
constexpr unsigned int API_CALL_TIMEOUT = 81; // 81s

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SERVICE_COMMON_H
