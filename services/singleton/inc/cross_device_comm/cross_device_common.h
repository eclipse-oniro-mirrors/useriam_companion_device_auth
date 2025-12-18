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

#ifndef COMPANION_DEVICE_AUTH_CROSS_DEVICE_COMMON_H
#define COMPANION_DEVICE_AUTH_CROSS_DEVICE_COMMON_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "cda_attributes.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

enum SubscribeMode : int32_t {
    SUBSCRIBE_MODE_AUTH = 0,
    SUBSCRIBE_MODE_MANAGE = 1,
};

class PhysicalDeviceKey {
public:
    PhysicalDeviceKey() = default;
    ~PhysicalDeviceKey() = default;

    bool operator==(const PhysicalDeviceKey &other) const
    {
        return idType == other.idType && deviceId == other.deviceId;
    }

    bool operator<(const PhysicalDeviceKey &other) const
    {
        if (idType != other.idType) {
            return idType < other.idType;
        }
        return deviceId < other.deviceId;
    }

    DeviceIdType idType { DeviceIdType::UNKNOWN };
    std::string deviceId {};
};

struct PhysicalDeviceStatus {
public:
    PhysicalDeviceKey physicalDeviceKey;
    ChannelId channelId { ChannelId::INVALID };
    std::string deviceName;
    std::string deviceModelInfo;
    std::string networkId {};
    bool isAuthMaintainActive { false };

    bool operator==(const PhysicalDeviceStatus &other) const
    {
        return physicalDeviceKey == other.physicalDeviceKey && channelId == other.channelId &&
            deviceName == other.deviceName && deviceModelInfo == other.deviceModelInfo &&
            isAuthMaintainActive == other.isAuthMaintainActive;
    }
};

using OnDeviceStatusChange = std::function<void(const std::vector<DeviceStatus> &deviceStatusList)>;
using OnLocalDeviceStatusChange = std::function<void(const LocalDeviceStatus &status)>;
using OnMessageReply = std::function<void(const Attributes &reply)>;
using OnMessage = std::function<void(const Attributes &request, OnMessageReply &onMessageReply)>;

using OnPhysicalDeviceStatusChange = std::function<void(const std::vector<PhysicalDeviceStatus> &deviceStatusList)>;
using OnAuthMaintainActiveChange = std::function<void(bool isActive)>;

enum class ConnectionStatus : int32_t {
    ESTABLISHING = 0,
    CONNECTED = 1,
    DISCONNECTED = 2,
};

inline ConnectionStatus ConvertToConnectionStatus(bool isConnected, const std::string &reason)
{
    if (isConnected) {
        return ConnectionStatus::CONNECTED;
    }
    return ConnectionStatus::DISCONNECTED;
}

using OnConnectionStatusChange =
    std::function<void(const std::string &connectionName, ConnectionStatus status, const std::string &reason)>;

using OnRawMessage = std::function<void(const std::string &connectionName, const std::vector<uint8_t> &msg)>;

using OnIncomingConnection =
    std::function<void(const std::string &connectionName, const PhysicalDeviceKey &remotePhysicalDeviceKey)>;

using OnCheckOperationIntentResult = std::function<void(bool confirmed)>;

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CROSS_DEVICE_COMMON_H
