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

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "common_defines.h"
#include "iam_para2str.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FwkResultCallback = std::function<void(ResultCode result, const std::vector<uint8_t> &extraInfo)>;

using RequestId = int32_t;
using TemplateId = uint64_t;
using ScheduleId = uint64_t;
using UserId = int32_t;
using BindingId = uint32_t;
using BusinessIdType = int32_t;
using SubscribeId = int32_t;
using Atl = int32_t;

enum class ChannelId : int32_t {
    INVALID = 0,
    SOFTBUS = 1,
    HEAD_PHONE_MANAGER = 10001,
    GLASSES_MANAGER = 10002,
};

enum class Capability : uint16_t {
    INVALID = 0,
    DELEGATE_AUTH = 1,
    TOKEN_AUTH = 2,
};

enum class ProtocolId : uint16_t {
    INVALID = 0,
    VERSION_1 = 1,
};

enum class SecureProtocolId : uint16_t {
    INVALID = 0,
    DEFAULT = 1,
    MCU = 2,
    MCU_AP = 3,
};

constexpr int32_t INVALID_USER_ID = -1;

enum class MessageType : uint16_t {
    // Invalid
    INVALID = 0x0000,
    // Device status sync (0x01xx)
    SYNC_DEVICE_STATUS = 0x0101,

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

    // Auth state maintenance (0x09xx)
    AUTH_MAINTAIN_STATE_CHANGE = 0x0901,

    // Companion pbtain token (0x0Axx)
    PRE_OBTAIN_TOKEN = 0x0A01,
    OBTAIN_TOKEN = 0x0A02,

    // Keep alive (0x0Bxx)
    KEEP_ALIVE = 0x0B01,
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

    DeviceIdType idType { DeviceIdType::UNKNOWN };
    std::string deviceId {};
    UserId deviceUserId { -1 };
};

class DeviceStatus {
public:
    bool operator==(const DeviceStatus &other) const
    {
        return deviceKey == other.deviceKey && channelId == other.channelId &&
            deviceModelInfo == other.deviceModelInfo && deviceUserName == other.deviceUserName &&
            deviceName == other.deviceName && protocolId == other.protocolId &&
            secureProtocolId == other.secureProtocolId && capabilities == other.capabilities &&
            supportedBusinessIds == other.supportedBusinessIds && isOnline == other.isOnline;
    }

    DeviceKey deviceKey {};
    ChannelId channelId { ChannelId::INVALID };
    std::string deviceModelInfo {};
    std::string deviceUserName {};
    std::string deviceName {};
    ProtocolId protocolId { ProtocolId::INVALID };
    SecureProtocolId secureProtocolId { SecureProtocolId::INVALID };
    std::vector<Capability> capabilities {};
    std::vector<BusinessIdType> supportedBusinessIds {};
    bool isOnline { false };
    bool isAuthMaintainActive { false };
};

struct LocalDeviceStatus {
    std::map<ChannelId, DeviceKey> channelId2DeviceKey;
    std::vector<ProtocolId> protocols;
    std::vector<SecureProtocolId> hostSecureProtocols;
    SecureProtocolId companionSecureProtocolId { SecureProtocolId::INVALID };
    std::vector<Capability> capabilities;
    std::vector<ProtocolId> protocolPriorityList;
    std::string deviceUserName;
    std::string deviceName;
    std::string deviceModelInfo;
    bool isAuthMaintainActive { false };
};

struct PersistedCompanionStatus {
    TemplateId templateId { 0 };
    UserId hostUserId { -1 };
    DeviceKey companionDeviceKey {};
    bool isValid { false };
    std::vector<BusinessIdType> enabledBusinessIds {};
    int64_t addedTime { 0 };
    SecureProtocolId secureProtocolId { SecureProtocolId::INVALID };
    std::string deviceModelInfo {};
    std::string deviceUserName {};
    std::string deviceName {};
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
        companionDeviceStatus.secureProtocolId = persistedStatus.secureProtocolId;
        companionDeviceStatus.deviceModelInfo = persistedStatus.deviceModelInfo;
        companionDeviceStatus.deviceUserName = persistedStatus.deviceUserName;
        companionDeviceStatus.deviceName = persistedStatus.deviceName;
        tokenAtl = std::nullopt;
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
        persistedStatus.secureProtocolId = companionDeviceStatus.secureProtocolId;
        persistedStatus.deviceModelInfo = companionDeviceStatus.deviceModelInfo;
        persistedStatus.deviceUserName = companionDeviceStatus.deviceUserName;
        persistedStatus.deviceName = companionDeviceStatus.deviceName;
        return persistedStatus;
    }

    TemplateId templateId { 0 };
    UserId hostUserId { -1 };
    DeviceStatus companionDeviceStatus {};
    bool isValid { true };
    std::optional<Atl> tokenAtl { std::nullopt };
    std::vector<BusinessIdType> enabledBusinessIds {};
    int64_t addedTime { 0 };
    int64_t lastCheckTime { 0 };
};

struct HostBindingStatus {
    BindingId bindingId { 0 };
    UserId companionUserId { -1 };
    DeviceStatus hostDeviceStatus {};
    bool isTokenValid { false };
    bool localAuthMaintainActive { false };
};

struct PersistedHostBindingStatus {
    BindingId bindingId { 0 };
    UserId companionUserId { -1 };
    DeviceKey hostDeviceKey {};
    bool isTokenValid { false };
};

struct SecureExecutorInfo {
    int32_t esl { 0 };
    uint32_t maxTemplateAcl { 0 };
    std::vector<uint8_t> publicKey {};
};

struct SyncDeviceStatus {
    DeviceKey deviceKey {};
    std::vector<ProtocolId> protocolIdList;
    std::vector<Capability> capabilityList;
    SecureProtocolId secureProtocolId;
    std::string deviceUserName {};
};

constexpr uint32_t DEFAULT_REQUEST_TIMEOUT_MS = 60 * 1000; // 60 seconds
constexpr uint32_t TOKEN_TIMEOUT_MS = 4 * 60 * 60 * 1000;  // 4 hours
constexpr std::chrono::seconds IDLE_THRESHOLD { 10 };
constexpr uint32_t IDLE_MONITOR_INTERVAL_MS = 10 * 1000; // 10 seconds
constexpr uint32_t MAX_SYNC_WAIT_TIME_SEC = 1;           // 1 second
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SERVICE_COMMON_H
