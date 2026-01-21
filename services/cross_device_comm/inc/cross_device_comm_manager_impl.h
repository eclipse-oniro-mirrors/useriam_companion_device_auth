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

#ifndef COMPANION_DEVICE_AUTH_CROSS_DEVICE_COMM_MANAGER_IMPL_H
#define COMPANION_DEVICE_AUTH_CROSS_DEVICE_COMM_MANAGER_IMPL_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "channel_manager.h"
#include "companion_manager.h"
#include "connection_manager.h"
#include "cross_device_comm_manager.h"
#include "cross_device_common.h"
#include "device_status_manager.h"
#include "icross_device_channel.h"
#include "local_device_status_manager.h"
#include "message_router.h"
#include "misc_manager.h"
#include "service_common.h"
#include "subscription.h"
#include "system_param_manager.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CrossDeviceCommManagerImpl : public ICrossDeviceCommManager {
public:
    static std::shared_ptr<CrossDeviceCommManagerImpl> Create(
        const std::vector<std::shared_ptr<ICrossDeviceChannel>> &channels);

    ~CrossDeviceCommManagerImpl() override = default;

    bool Start() override;
    bool IsAuthMaintainActive() override;
    std::unique_ptr<Subscription> SubscribeIsAuthMaintainActive(OnAuthMaintainActiveChange &&callback) override;
    LocalDeviceProfile GetLocalDeviceProfile() override;
    std::optional<DeviceStatus> GetDeviceStatus(const DeviceKey &deviceKey) override;
    std::vector<DeviceStatus> GetAllDeviceStatus() override;
    std::unique_ptr<Subscription> SubscribeAllDeviceStatus(OnDeviceStatusChange &&onDeviceStatusChange) override;
    void SetSubscribeMode(SubscribeMode subscribeMode) override;
    std::optional<SteadyTimeMs> GetManageSubscribeTime() const override;
    std::unique_ptr<Subscription> SubscribeDeviceStatus(const DeviceKey &deviceKey,
        OnDeviceStatusChange &&onDeviceStatusChange) override;
    bool OpenConnection(const DeviceKey &deviceKey, std::string &outConnectionName) override;
    void CloseConnection(const std::string &connectionName) override;
    bool IsConnectionOpen(const std::string &connectionName) override;
    ConnectionStatus GetConnectionStatus(const std::string &connectionName) override;
    std::optional<DeviceKey> GetLocalDeviceKeyByConnectionName(const std::string &connectionName) override;
    std::unique_ptr<Subscription> SubscribeConnectionStatus(const std::string &connectionName,
        OnConnectionStatusChange &&onConnectionStatusChange) override;
    std::unique_ptr<Subscription> SubscribeIncomingConnection(MessageType msgType, OnMessage &&onMessage) override;
    bool SendMessage(const std::string &connectionName, MessageType msgType, Attributes &request,
        OnMessageReply &&onMessageReply) override;
    std::unique_ptr<Subscription> SubscribeMessage(const std::string &connectionName, MessageType msgType,
        OnMessage &&onMessage) override;
    bool CheckOperationIntent(const DeviceKey &deviceKey, uint32_t tokenId,
        OnCheckOperationIntentResult &&resultCallback) override;

    std::optional<SecureProtocolId> HostGetSecureProtocolId(const DeviceKey &companionDeviceKey) override;
    SecureProtocolId CompanionGetSecureProtocolId() override;

private:
    CrossDeviceCommManagerImpl(std::shared_ptr<ChannelManager> channelMgr,
        std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr,
        std::shared_ptr<ConnectionManager> connectionMgr, std::shared_ptr<MessageRouter> messageRouter,
        std::shared_ptr<DeviceStatusManager> deviceStatusMgr);

    std::shared_ptr<ChannelManager> channelMgr_;
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr_;
    std::shared_ptr<ConnectionManager> connectionMgr_;
    std::shared_ptr<MessageRouter> messageRouter_;
    std::shared_ptr<DeviceStatusManager> deviceStatusMgr_;
    bool started_ = false;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CROSS_DEVICE_COMM_MANAGER_IMPL_H
