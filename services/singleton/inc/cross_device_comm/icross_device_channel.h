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

#ifndef COMPANION_DEVICE_AUTH_ICROSS_DEVICE_CHANNEL_H
#define COMPANION_DEVICE_AUTH_ICROSS_DEVICE_CHANNEL_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "cross_device_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class ICrossDeviceChannel {
public:
    virtual ~ICrossDeviceChannel() = default;

    virtual bool Start() = 0;

    virtual ChannelId GetChannelId() const = 0;
    virtual std::optional<PhysicalDeviceKey> GetLocalPhysicalDeviceKey() const = 0;

    virtual bool OpenConnection(const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey) = 0;
    virtual void CloseConnection(const std::string &connectionName) = 0;
    virtual bool RequiresDisconnectNotification() const = 0;
    virtual void OnRemoteDisconnect(const std::string &connectionName, const std::string &reason) = 0;
    virtual bool SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg) = 0;

    virtual std::unique_ptr<Subscription> SubscribePhysicalDeviceStatus(OnPhysicalDeviceStatusChange &&callback) = 0;
    virtual std::vector<PhysicalDeviceStatus> GetAllPhysicalDevices() const = 0;
    virtual std::unique_ptr<Subscription> SubscribeRawMessage(OnRawMessage &&callback) = 0;
    virtual std::unique_ptr<Subscription> SubscribeConnectionStatus(OnConnectionStatusChange &&callback) = 0;
    virtual std::unique_ptr<Subscription> SubscribeIncomingConnection(OnIncomingConnection &&callback) = 0;

    virtual bool GetAuthMaintainActive() const = 0;
    virtual std::unique_ptr<Subscription> SubscribeAuthMaintainActive(OnAuthMaintainActiveChange &&callback) = 0;

    virtual SecureProtocolId GetCompanionSecureProtocolId() const = 0;

    virtual bool CheckOperationIntent(const DeviceKey &deviceKey, uint32_t tokenId,
        OnCheckOperationIntentResult &&resultCallback) = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ICROSS_DEVICE_CHANNEL_H
