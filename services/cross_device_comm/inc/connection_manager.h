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

#ifndef COMPANION_DEVICE_AUTH_CONNECTION_MANAGER_H
#define COMPANION_DEVICE_AUTH_CONNECTION_MANAGER_H

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include "nocopyable.h"

#include "cda_attributes.h"
#include "channel_manager.h"
#include "cross_device_common.h"
#include "icross_device_channel.h"
#include "local_device_status_manager.h"
#include "misc_manager.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MessageRouter;

struct Connection {
    std::string connectionName;
    PhysicalDeviceKey remotePhysicalDeviceKey;
    ChannelId channelId;
    ConnectionStatus connectionStatus;
    bool isInbound { false };
    SteadyTimeMs createTimeMs { 0 };
    SteadyTimeMs lastActivityTimeMs { 0 };
};

class ConnectionManager : public std::enable_shared_from_this<ConnectionManager>, public NoCopyable {
public:
    static std::shared_ptr<ConnectionManager> Create(std::shared_ptr<ChannelManager> channelManager,
        std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusManager);

    ~ConnectionManager();

    void SetMessageRouter(std::weak_ptr<MessageRouter> messageRouter);

    bool OpenConnection(const PhysicalDeviceKey &physicalDeviceKey, ChannelId channelId,
        std::string &outConnectionName);
    void CloseConnection(const std::string &connectionName, const std::string &reason = "not_set");
    bool HandleIncomingConnection(const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey);

    std::optional<Connection> GetConnection(const std::string &connectionName)
    {
        auto it = connectionMap_.find(connectionName);
        if (it != connectionMap_.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    ConnectionStatus GetConnectionStatus(const std::string &connectionName)
    {
        auto connection = GetConnection(connectionName);
        if (!connection.has_value()) {
            return ConnectionStatus::DISCONNECTED;
        }
        return connection->connectionStatus;
    }

    std::unique_ptr<Subscription> SubscribeConnectionStatus(const std::string &connectionName,
        OnConnectionStatusChange &&callback);

    void HandleChannelConnectionStatusChange(const std::string &connectionName, ConnectionStatus status,
        const std::string &reason);
    void HandleKeepAliveReply(const std::string &connectionName, const Attributes &reply);

private:
    ConnectionManager(std::shared_ptr<ChannelManager> channelManager,
        std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusManager);
    bool Initialize();

    // Resource limits
    static constexpr size_t MAX_GLOBAL_CONNECTIONS = 100;
    static constexpr size_t MAX_DEVICE_CONNECTIONS = 10;

    std::weak_ptr<MessageRouter> weakMessageRouter_;

    // Connection management
    std::map<std::string, Connection> connectionMap_;

    // Channel management
    std::shared_ptr<ChannelManager> channelManager_;

    // Local device status management
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusManager_;

    // Subscription management
    struct ConnectionStatusSubscription {
        std::string connectionName;
        OnConnectionStatusChange callback;
    };
    std::map<SubscribeId, ConnectionStatusSubscription> connectionStatusSubscribers_;

    // Channel subscriptions
    std::map<ChannelId, std::unique_ptr<Subscription>> channelSubscriptions_;
    std::map<ChannelId, std::unique_ptr<Subscription>> incomingConnectionSubscriptions_;

    // Idle connection monitoring
    std::unique_ptr<Subscription> idleMonitorTimerSubscription_;

    std::vector<std::unique_ptr<Subscription>> physicalDeviceSubscriptions_;

    // Helper methods
    std::string GenerateConnectionName(const PhysicalDeviceKey &localPhysicalKey,
        const PhysicalDeviceKey &remotePhysicalKey);
    bool CheckResourceLimits(const PhysicalDeviceKey &physicalDeviceKey);
    void CheckIdleMonitoring();
    void StopIdleMonitoring();
    void HandleIdleMonitorTimer();

    void HandleChannelConnectionEstablished(const std::string &connectionName);
    void HandleChannelConnectionClosed(const std::string &connectionName, const std::string &reason);
    void HandleIncomingConnectionFromChannel(ChannelId channelId, const std::string &connectionName,
        const PhysicalDeviceKey &remotePhysicalDeviceKey);
    void HandlePhysicalDeviceStatusChange(ChannelId channelId, const std::vector<PhysicalDeviceStatus> &statusList);
    void NotifyConnectionStatus(const std::string &connectionName, ConnectionStatus status, const std::string &reason);
    void UnsubscribeConnectionStatus(SubscribeId subscriptionId);
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CONNECTION_MANAGER_H
