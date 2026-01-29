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

#include "connection_manager.h"

#include <cinttypes>
#include <iomanip>
#include <sstream>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "adapter_manager.h"
#include "common_defines.h"
#include "device_status_manager.h"
#include "local_device_status_manager.h"
#include "message_router.h"
#include "relative_timer.h"
#include "scope_guard.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "time_keeper.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<ConnectionManager> ConnectionManager::Create(std::shared_ptr<ChannelManager> channelManager,
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusManager)
{
    auto manager = std::shared_ptr<ConnectionManager>(
        new (std::nothrow) ConnectionManager(channelManager, localDeviceStatusManager));
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);

    if (!manager->Initialize()) {
        IAM_LOGE("failed to initialize ConnectionManager");
        return nullptr;
    }

    return manager;
}

ConnectionManager::ConnectionManager(std::shared_ptr<ChannelManager> channelManager,
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusManager)
    : channelManager_(channelManager),
      localDeviceStatusManager_(localDeviceStatusManager),
      idleMonitorTimerSubscription_(nullptr)
{
}

ConnectionManager::~ConnectionManager()
{
}

void ConnectionManager::SetMessageRouter(std::weak_ptr<MessageRouter> messageRouter)
{
    weakMessageRouter_ = messageRouter;
}

bool ConnectionManager::Initialize()
{
    ENSURE_OR_RETURN_VAL(channelManager_ != nullptr, false);

    for (const auto &channel : channelManager_->GetAllChannels()) {
        ENSURE_OR_CONTINUE(channel != nullptr);
        ChannelId channelId = channel->GetChannelId();
        auto subscription =
            channel->SubscribeConnectionStatus([weakSelf = weak_from_this()](const std::string &connectionName,
                                                   ConnectionStatus status, const std::string &reason) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleChannelConnectionStatusChange(connectionName, status, reason);
            });
        ENSURE_OR_RETURN_VAL(subscription != nullptr, false);
        channelSubscriptions_[channelId] = std::move(subscription);

        auto incomingSubscription = channel->SubscribeIncomingConnection(
            [weakSelf = weak_from_this(), channelId](const std::string &connectionName,
                const PhysicalDeviceKey &remotePhysicalDeviceKey) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleIncomingConnectionFromChannel(channelId, connectionName, remotePhysicalDeviceKey);
            });
        ENSURE_OR_RETURN_VAL(incomingSubscription != nullptr, false);
        incomingConnectionSubscriptions_[channelId] = std::move(incomingSubscription);

        auto physicalDeviceSubscription = channel->SubscribePhysicalDeviceStatus(
            [weakSelf = weak_from_this(), channelId](const std::vector<PhysicalDeviceStatus> &statusList) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandlePhysicalDeviceStatusChange(channelId, statusList);
            });
        ENSURE_OR_RETURN_VAL(physicalDeviceSubscription != nullptr, false);
        physicalDeviceSubscriptions_.push_back(std::move(physicalDeviceSubscription));
    }

    return true;
}

bool ConnectionManager::OpenConnection(const PhysicalDeviceKey &physicalDeviceKey, ChannelId channelId,
    std::string &outConnectionName)
{
    IAM_LOGI("opening connection to physical device: type=%{public}d id=%{public}s on channel: %{public}d",
        static_cast<int32_t>(physicalDeviceKey.idType), GetMaskedString(physicalDeviceKey.deviceId).c_str(), channelId);

    ENSURE_OR_RETURN_VAL(CheckResourceLimits(physicalDeviceKey), false);

    auto channel = channelManager_->GetChannelById(channelId);
    ENSURE_OR_RETURN_VAL(channel != nullptr, false);

    auto localPhysicalKeyOpt = channel->GetLocalPhysicalDeviceKey();
    ENSURE_OR_RETURN_VAL(localPhysicalKeyOpt.has_value(), false);
    const auto &localPhysicalKey = localPhysicalKeyOpt.value();
    ENSURE_OR_RETURN_VAL(localPhysicalKey.idType != DeviceIdType::UNKNOWN, false);
    ENSURE_OR_RETURN_VAL(!localPhysicalKey.deviceId.empty(), false);

    std::string connectionName = GenerateConnectionName(localPhysicalKey, physicalDeviceKey);

    Connection connection {};
    connection.connectionName = connectionName;
    connection.remotePhysicalDeviceKey = physicalDeviceKey;
    connection.channelId = channel->GetChannelId();
    connection.connectionStatus = ConnectionStatus::ESTABLISHING;
    connection.isInbound = false;
    auto createTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN_VAL(createTimeMs.has_value(), false);
    connection.createTimeMs = createTimeMs.value();
    connection.lastActivityTimeMs = connection.createTimeMs;

    bool success = channel->OpenConnection(connectionName, physicalDeviceKey);
    if (!success) {
        IAM_LOGE("failed to open physical connection");
        return false;
    }

    outConnectionName = connectionName;
    connectionMap_[connectionName] = connection;
    CheckIdleMonitoring();
    NotifyConnectionStatus(connectionName, ConnectionStatus::ESTABLISHING, "establishing");
    IAM_LOGI("connection opened: %{public}s", connectionName.c_str());
    return true;
}

void ConnectionManager::CloseConnection(const std::string &connectionName, const std::string &reason)
{
    IAM_LOGI("closing connection: %{public}s, reason: %{public}s", connectionName.c_str(), reason.c_str());

    auto it = connectionMap_.find(connectionName);
    if (it == connectionMap_.end()) {
        IAM_LOGW("connection not found: %{public}s", connectionName.c_str());
        return;
    }

    Connection connection = it->second;
    ChannelId channelId = connection.channelId;
    ScopeGuard guard([this, &connectionName]() { connectionMap_.erase(connectionName); });

    auto channel = channelManager_->GetChannelById(channelId);
    ENSURE_OR_RETURN(channel != nullptr);

    if (channel->RequiresDisconnectNotification() && !connection.isInbound) {
        Attributes request;
        request.SetStringValue(Attributes::ATTR_CDA_SA_REASON, reason);

        auto messageRouter = weakMessageRouter_.lock();
        ENSURE_OR_RETURN(messageRouter != nullptr);

        bool sendRet = messageRouter->SendMessage(connectionName, MessageType::DISCONNECT, request,
            [connectionName](const Attributes &) {
                IAM_LOGE("unexpected reply to disconnect request for: %{public}s", connectionName.c_str());
            });
        if (!sendRet) {
            IAM_LOGE("failed to send disconnect request for: %{public}s", connectionName.c_str());
        }
    }

    if (connection.isInbound) {
        channel->OnRemoteDisconnect(connectionName, reason);
    } else {
        channel->CloseConnection(connectionName);
    }

    // Erase the connection before checking idle monitoring status
    connectionMap_.erase(connectionName);
    guard.Cancel();
    CheckIdleMonitoring();

    NotifyConnectionStatus(connectionName, ConnectionStatus::DISCONNECTED, reason);

    IAM_LOGI("connection closed: %{public}s", connectionName.c_str());
}

bool ConnectionManager::HandleIncomingConnection(const std::string &connectionName,
    const PhysicalDeviceKey &physicalDeviceKey)
{
    IAM_LOGI("handling incoming connection: %{public}s, deviceId=%{public}s", connectionName.c_str(),
        GET_MASKED_STR_CSTR(physicalDeviceKey.deviceId));

    if (connectionMap_.find(connectionName) != connectionMap_.end()) {
        IAM_LOGW("connection already exists: %{public}s", connectionName.c_str());
        return false;
    }

    if (!CheckResourceLimits(physicalDeviceKey)) {
        IAM_LOGE("resource limit check failed for incoming connection: %{public}s", connectionName.c_str());
        return false;
    }

    // Find the channel that can handle this device
    std::shared_ptr<ICrossDeviceChannel> targetChannel = nullptr;
    ChannelId targetChannelId = ChannelId::INVALID;

    for (const auto &channel : channelManager_->GetAllChannels()) {
        ENSURE_OR_CONTINUE(channel != nullptr);
        auto localKeyOpt = channel->GetLocalPhysicalDeviceKey();
        if (!localKeyOpt.has_value()) {
            continue;
        }
        // For now, use the first available channel
        // In a real scenario, you might want to match based on device capabilities
        if (!targetChannel) {
            targetChannel = channel;
            targetChannelId = channel->GetChannelId();
            break;
        }
    }

    if (!targetChannel) {
        IAM_LOGE("no available channel for incoming connection: %{public}s", connectionName.c_str());
        return false;
    }

    // Create Connection
    Connection connection {};
    connection.connectionName = connectionName;
    connection.remotePhysicalDeviceKey = physicalDeviceKey;
    connection.channelId = targetChannelId;
    connection.connectionStatus = ConnectionStatus::CONNECTED;
    connection.isInbound = true;
    auto createTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN_VAL(createTimeMs.has_value(), false);
    connection.createTimeMs = createTimeMs.value();
    connection.lastActivityTimeMs = connection.createTimeMs;

    connectionMap_[connectionName] = connection;
    CheckIdleMonitoring();

    NotifyConnectionStatus(connectionName, ConnectionStatus::CONNECTED, "incoming_connection");

    IAM_LOGI("incoming connection created: %{public}s", connectionName.c_str());
    return true;
}

void ConnectionManager::HandleIncomingConnectionFromChannel(ChannelId channelId, const std::string &connectionName,
    const PhysicalDeviceKey &remotePhysicalDeviceKey)
{
    IAM_LOGI("incoming connection from channel: %{public}s, deviceId=%{public}s", connectionName.c_str(),
        GET_MASKED_STR_CSTR(remotePhysicalDeviceKey.deviceId));

    if (connectionMap_.find(connectionName) != connectionMap_.end()) {
        IAM_LOGW("connection already exists: %{public}s", connectionName.c_str());
        return;
    }

    if (!CheckResourceLimits(remotePhysicalDeviceKey)) {
        IAM_LOGE("resource limit check failed for incoming connection: %{public}s", connectionName.c_str());
        return;
    }

    // Create Connection
    Connection connection {};
    connection.connectionName = connectionName;
    connection.remotePhysicalDeviceKey = remotePhysicalDeviceKey;
    connection.channelId = channelId;
    connection.connectionStatus = ConnectionStatus::CONNECTED;
    connection.isInbound = true;
    auto createTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(createTimeMs.has_value());
    connection.createTimeMs = createTimeMs.value();
    connection.lastActivityTimeMs = connection.createTimeMs;

    connectionMap_[connectionName] = connection;
    CheckIdleMonitoring();

    NotifyConnectionStatus(connectionName, ConnectionStatus::CONNECTED, "incoming_connection");

    IAM_LOGI("incoming connection created: %{public}s", connectionName.c_str());
}

std::unique_ptr<Subscription> ConnectionManager::SubscribeConnectionStatus(const std::string &connectionName,
    OnConnectionStatusChange &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    ConnectionStatusSubscription subscription {};
    subscription.connectionName = connectionName;
    subscription.callback = std::move(callback);
    connectionStatusSubscribers_[subscriptionId] = std::move(subscription);

    IAM_LOGD("connection status subscription added: id=0x%{public}016" PRIX64 ", connection=%{public}s", subscriptionId,
        connectionName.empty() ? "all" : connectionName.c_str());

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeConnectionStatus(subscriptionId);
    });
}

void ConnectionManager::HandleChannelConnectionStatusChange(const std::string &connectionName, ConnectionStatus status,
    const std::string &reason)
{
    if (status == ConnectionStatus::CONNECTED) {
        HandleChannelConnectionEstablished(connectionName);
    } else if (status == ConnectionStatus::DISCONNECTED) {
        HandleChannelConnectionClosed(connectionName, reason);
    }
}

void ConnectionManager::HandleChannelConnectionEstablished(const std::string &connectionName)
{
    IAM_LOGI("connection established: %{public}s", connectionName.c_str());

    auto it = connectionMap_.find(connectionName);
    if (it == connectionMap_.end()) {
        IAM_LOGW("connection not found: %{public}s", connectionName.c_str());
        return;
    }

    it->second.connectionStatus = ConnectionStatus::CONNECTED;
    auto lastActivityTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(lastActivityTimeMs.has_value());
    it->second.lastActivityTimeMs = lastActivityTimeMs.value();

    NotifyConnectionStatus(connectionName, ConnectionStatus::CONNECTED, "established");
}

void ConnectionManager::HandleChannelConnectionClosed(const std::string &connectionName, const std::string &reason)
{
    IAM_LOGI("channel connection closed: %{public}s, reason: %{public}s", connectionName.c_str(), reason.c_str());

    auto it = connectionMap_.find(connectionName);
    if (it == connectionMap_.end()) {
        IAM_LOGI("connection not found: %{public}s", connectionName.c_str());
        return;
    }

    it->second.connectionStatus = ConnectionStatus::DISCONNECTED;
    NotifyConnectionStatus(connectionName, ConnectionStatus::DISCONNECTED, reason);
    connectionMap_.erase(it);
    CheckIdleMonitoring();

    IAM_LOGI("connection removed after passive close: %{public}s", connectionName.c_str());
}

std::string ConnectionManager::GenerateConnectionName(const PhysicalDeviceKey &localPhysicalKey,
    const PhysicalDeviceKey &remotePhysicalKey)
{
    constexpr int connectionIdWidth = 8;
    std::string localShort = GetTruncatedString(localPhysicalKey.deviceId);
    std::string remoteShort = GetTruncatedString(remotePhysicalKey.deviceId);

    uint32_t id = static_cast<uint32_t>(GetMiscManager().GetNextGlobalId());

    std::ostringstream oss;
    oss << localShort << ":" << remoteShort << ":" << std::hex << std::setfill('0') << std::setw(connectionIdWidth)
        << id;

    return oss.str();
}

bool ConnectionManager::CheckResourceLimits(const PhysicalDeviceKey &physicalDeviceKey)
{
    if (connectionMap_.size() >= MAX_GLOBAL_CONNECTIONS) {
        IAM_LOGE("global connection limit exceeded: %{public}zu/%{public}zu", connectionMap_.size(),
            MAX_GLOBAL_CONNECTIONS);
        return false;
    }

    size_t deviceConnectionCount = 0;
    for (const auto &pair : connectionMap_) {
        if (pair.second.remotePhysicalDeviceKey == physicalDeviceKey) {
            deviceConnectionCount++;
        }
    }

    if (deviceConnectionCount >= MAX_DEVICE_CONNECTIONS) {
        IAM_LOGE("device connection limit exceeded: %{public}zu/%{public}zu", deviceConnectionCount,
            MAX_DEVICE_CONNECTIONS);
        return false;
    }

    return true;
}

void ConnectionManager::CheckIdleMonitoring()
{
    bool hasConnections = !connectionMap_.empty();
    bool hasTimer = idleMonitorTimerSubscription_ != nullptr;

    if (hasConnections && !hasTimer) {
        idleMonitorTimerSubscription_ = RelativeTimer::GetInstance().RegisterPeriodic(
            [weakSelf = weak_from_this()]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleIdleMonitorTimer();
            },
            IDLE_MONITOR_INTERVAL_MS);
        ENSURE_OR_RETURN(idleMonitorTimerSubscription_ != nullptr);
        IAM_LOGI("idle monitoring started");
    } else if (!hasConnections && hasTimer) {
        StopIdleMonitoring();
    }
}

void ConnectionManager::StopIdleMonitoring()
{
    if (idleMonitorTimerSubscription_ != nullptr) {
        idleMonitorTimerSubscription_.reset();
        IAM_LOGI("idle monitoring stopped");
    }
}

void ConnectionManager::HandleIdleMonitorTimer()
{
    auto now = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(now.has_value());

    for (const auto &pair : connectionMap_) {
        const Connection &connection = pair.second;

        if (now.value() < connection.lastActivityTimeMs) {
            IAM_LOGW("clock anomaly detected for connection %{public}s, skipping idle check",
                connection.connectionName.c_str());
            continue;
        }

        auto idleTimeMs = now.value() - connection.lastActivityTimeMs;
        if (idleTimeMs >= IDLE_THRESHOLD_MS) {
            IAM_LOGW("connection idle for %{public}" PRIu64 " ms: %{public}s", idleTimeMs,
                connection.connectionName.c_str());
            auto messageRouter = weakMessageRouter_.lock();
            ENSURE_OR_RETURN(messageRouter != nullptr);
            Attributes request;
            bool sendMessageRet =
                messageRouter->SendMessage(connection.connectionName, MessageType::KEEP_ALIVE, request,
                    [weakSelf = weak_from_this(), connectionName = connection.connectionName](const Attributes &reply) {
                        auto self = weakSelf.lock();
                        ENSURE_OR_RETURN(self != nullptr);
                        self->HandleKeepAliveReply(connectionName, reply);
                    });
            ENSURE_OR_RETURN(sendMessageRet);
        }
    }
}

void ConnectionManager::HandleKeepAliveReply(const std::string &connectionName, const Attributes &reply)
{
    IAM_LOGI("keep alive reply received: %{public}s", connectionName.c_str());

    auto it = connectionMap_.find(connectionName);
    if (it == connectionMap_.end()) {
        IAM_LOGE("connection not found: %{public}s", connectionName.c_str());
        return;
    }

    int32_t result {};
    bool getResultRet = reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
    ENSURE_OR_RETURN(getResultRet);
    if (result != ResultCode::SUCCESS) {
        TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), connectionName]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->CloseConnection(connectionName, "keep_alive_reply_failed");
        });
        IAM_LOGI("keep alive reply failed: %{public}s", connectionName.c_str());
        return;
    }

    auto lastActivityTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(lastActivityTimeMs.has_value());
    it->second.lastActivityTimeMs = lastActivityTimeMs.value();
}

void ConnectionManager::NotifyConnectionStatus(const std::string &connectionName, ConnectionStatus status,
    const std::string &reason)
{
    std::vector<OnConnectionStatusChange> callbacks;
    callbacks.reserve(connectionStatusSubscribers_.size());
    for (const auto &pair : connectionStatusSubscribers_) {
        const ConnectionStatusSubscription &subscription = pair.second;
        if (!subscription.callback) {
            continue;
        }
        if (subscription.connectionName.empty() || subscription.connectionName == connectionName) {
            callbacks.push_back(subscription.callback);
        }
    }

    if (callbacks.empty()) {
        return;
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [callbacks = std::move(callbacks), connectionName, status, reason]() {
            for (auto &cb : callbacks) {
                if (cb) {
                    cb(connectionName, status, reason);
                }
            }
        });
}

void ConnectionManager::UnsubscribeConnectionStatus(SubscribeId subscriptionId)
{
    connectionStatusSubscribers_.erase(subscriptionId);
    IAM_LOGD("connection status subscription removed: id=0x%{public}016" PRIX64 "", subscriptionId);
}

void ConnectionManager::HandlePhysicalDeviceStatusChange(ChannelId channelId,
    const std::vector<PhysicalDeviceStatus> &statusList)
{
    IAM_LOGI("physical device status changed for channel=%{public}d: device count=%{public}zu", channelId,
        statusList.size());

    std::vector<std::string> connectionsToClose;
    for (const auto &pair : connectionMap_) {
        const Connection &connection = pair.second;

        if (connection.channelId != channelId) {
            continue;
        }

        bool deviceOnline = false;
        for (const auto &deviceStatus : statusList) {
            if (deviceStatus.physicalDeviceKey == connection.remotePhysicalDeviceKey) {
                deviceOnline = true;
                break;
            }
        }

        if (!deviceOnline) {
            connectionsToClose.push_back(connection.connectionName);
            IAM_LOGI(
                "marking connection for closure: %{public}s (device offline on channel: type=%{public}d id=%{public}s)",
                connection.connectionName.c_str(), static_cast<int32_t>(connection.remotePhysicalDeviceKey.idType),
                GetMaskedString(connection.remotePhysicalDeviceKey.deviceId).c_str());
        }
    }

    if (!connectionsToClose.empty()) {
        for (const auto &connectionName : connectionsToClose) {
            CloseConnection(connectionName, "device_down");
        }
        IAM_LOGI("closed %{public}zu connections due to devices going offline on channel=%{public}d",
            connectionsToClose.size(), channelId);
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
