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

#ifndef COMPANION_DEVICE_AUTH_SINGLETON_CROSS_DEVICE_COMM_MANAGER_H
#define COMPANION_DEVICE_AUTH_SINGLETON_CROSS_DEVICE_COMM_MANAGER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "cross_device_common.h"
#include "icross_device_channel.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class ICrossDeviceCommManager : public NoCopyable, public std::enable_shared_from_this<ICrossDeviceCommManager> {
public:
    virtual ~ICrossDeviceCommManager() = default;

    virtual bool Start() = 0;

    virtual bool IsAuthMaintainActive() = 0;
    virtual LocalDeviceProfile GetLocalDeviceProfile() = 0;
    virtual std::unique_ptr<Subscription> SubscribeIsAuthMaintainActive(OnAuthMaintainActiveChange &&callback) = 0;

    virtual std::optional<DeviceStatus> GetDeviceStatus(const DeviceKey &deviceKey) = 0;
    virtual std::vector<DeviceStatus> GetAllDeviceStatus() = 0;
    virtual std::unique_ptr<Subscription> SubscribeAllDeviceStatus(OnDeviceStatusChange &&onDeviceStatusChange) = 0;
    virtual std::unique_ptr<Subscription> SubscribeDeviceStatus(const DeviceKey &deviceKey,
        OnDeviceStatusChange &&onDeviceStatusChange) = 0;
    virtual void SetSubscribeMode(SubscribeMode subscribeMode) = 0;
    virtual std::optional<SteadyTimeMs> GetManageSubscribeTime() const = 0;

    virtual bool OpenConnection(const DeviceKey &deviceKey, std::string &outConnectionName) = 0;
    virtual void CloseConnection(const std::string &connectionName) = 0;
    virtual bool IsConnectionOpen(const std::string &connectionName) = 0;
    virtual ConnectionStatus GetConnectionStatus(const std::string &connectionName) = 0;
    virtual std::optional<DeviceKey> GetLocalDeviceKeyByConnectionName(const std::string &connectionName) = 0;
    virtual std::unique_ptr<Subscription> SubscribeConnectionStatus(const std::string &connectionName,
        OnConnectionStatusChange &&onConnectionStatusChange) = 0;
    virtual std::unique_ptr<Subscription> SubscribeIncomingConnection(MessageType msgType, OnMessage &&onMessage) = 0;

    virtual bool SendMessage(const std::string &connectionName, MessageType msgType, Attributes &request,
        OnMessageReply &&onMessageReply) = 0;
    virtual std::unique_ptr<Subscription> SubscribeMessage(const std::string &connectionName, MessageType msgType,
        OnMessage &&onMessage) = 0;

    virtual bool CheckOperationIntent(const DeviceKey &deviceKey, uint32_t tokenId,
        OnCheckOperationIntentResult &&resultCallback) = 0;

    virtual std::optional<SecureProtocolId> HostGetSecureProtocolId(const DeviceKey &companionDeviceKey) = 0;
    virtual SecureProtocolId CompanionGetSecureProtocolId() = 0;

protected:
    ICrossDeviceCommManager() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SINGLETON_CROSS_DEVICE_COMM_MANAGER_H
