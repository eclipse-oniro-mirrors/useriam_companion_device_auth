/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "soft_bus_connection_manager.h"

#include <algorithm>
#include <cinttypes>
#include <iomanip>
#include <sstream>
#include <utility>

#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "cda_attributes.h"
#include "cda_scope_guard.h"
#include "iam_safe_arithmetic.h"
#include "relative_timer.h"
#include "sa_status_listener.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "soft_bus_adapter_manager.h"
#include "soft_bus_channel_common.h"
#include "soft_bus_connection.h"
#include "softbus_error_code.h"
#include "subscription.h"
#include "task_runner_manager.h"
#include "time_keeper.h"

#include "iam_para2str.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SOFT_BUS_CONNECTION_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr const char *SOFTBUS_SA_NAME = "SoftBusServer";
constexpr size_t MAX_SOFTBUS_CONNECTIONS = 200;
constexpr size_t MAX_CONNECTION_NAME_LEN = 256;
// Grace period for an inbound connection to deliver its first message carrying
// the connection name; sockets still unnamed afterwards are force-closed so a
// misbehaving peer cannot exhaust the connection quota.
constexpr uint32_t INBOUND_NAMING_TIMEOUT_MS = 10000;
// Periodic sweep cadence for the naming monitor. With interval = timeout / 2,
// an unnamed socket is reclaimed within [timeout, timeout + interval) of accept.
constexpr uint32_t INBOUND_NAMING_MONITOR_INTERVAL_MS = 5000;

bool IsValidInboundConnectionName(const std::string &connectionName, const PhysicalDeviceKey &peerKey)
{
    if (connectionName.empty() || connectionName.size() > MAX_CONNECTION_NAME_LEN) {
        IAM_LOGE("connectionName length invalid: %{public}zu", connectionName.size());
        return false;
    }
    auto localKeyOpt = GetCrossDeviceCommManager().GetLocalDeviceKey(ChannelId::SOFTBUS);
    if (!localKeyOpt.has_value()) {
        IAM_LOGE("Failed to get local device key");
        return false;
    }
    std::string localShort = GetTruncatedString(localKeyOpt.value().deviceId);
    std::string remoteShort = GetTruncatedString(peerKey.deviceId);
    std::string expectedPrefix = remoteShort + ":" + localShort + ":";
    if (connectionName.compare(0, expectedPrefix.size(), expectedPrefix) != 0) {
        IAM_LOGE("connectionName prefix mismatch: %{public}s, expected prefix: %{public}s", connectionName.c_str(),
            expectedPrefix.c_str());
        return false;
    }
    return true;
}
} // namespace

std::shared_ptr<SoftBusConnectionManager> SoftBusConnectionManager::Create()
{
    auto manager = std::shared_ptr<SoftBusConnectionManager>(new (std::nothrow) SoftBusConnectionManager());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    bool ret = manager->Initialize();
    if (!ret) {
        IAM_LOGE("Initialize SoftBusConnectionManager failed");
        return nullptr;
    }

    return manager;
}

SoftBusConnectionManager::SoftBusConnectionManager()
{
}

SoftBusConnectionManager::~SoftBusConnectionManager()
{
    CloseAllSockets("destroy");
    IAM_LOGI("SoftBusConnectionManager destroyed");
}

bool SoftBusConnectionManager::Initialize()
{
    return true;
}

bool SoftBusConnectionManager::Start()
{
    if (started_) {
        IAM_LOGI("SoftBusConnectionManager already started");
        return true;
    }

    // Register callback with SoftBusAdapter
    {
        GetSoftBusAdapter().RegisterCallback(shared_from_this());
    }

    std::weak_ptr<SoftBusConnectionManager> weakSelf = weak_from_this();
    saStatusListener_ = SaStatusListener::Create(
        SOFTBUS_SA_NAME, SOFTBUS_SERVER_SA_ID,
        [weakSelf]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleSoftBusServiceReady();
        },
        [weakSelf]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleSoftBusServiceUnavailable();
        });
    ENSURE_OR_RETURN_VAL(saStatusListener_, false);

    started_ = true;
    return true;
}

bool SoftBusConnectionManager::StartServerSocket()
{
    if (serverSocketId_.has_value()) {
        IAM_LOGI("Server socket already created: %{public}d", serverSocketId_.value());
        return true;
    }

    auto socketId = GetSoftBusAdapter().CreateServerSocket();
    if (!socketId.has_value()) {
        IAM_LOGE("Create server socket failed");
        return false;
    }

    serverSocketId_ = socketId.value();

    IAM_LOGI("Server socket created and listening: %{public}d", socketId.value());
    return true;
}

bool SoftBusConnectionManager::OpenConnection(const std::string &connectionName,
    const PhysicalDeviceKey &physicalDeviceKey, const std::string &networkId)
{
    if (FindSocketByConnectionName(connectionName) != nullptr) {
        IAM_LOGE("Connection already exists: %{public}s", connectionName.c_str());
        return false;
    }

    if (connections_.size() >= MAX_SOFTBUS_CONNECTIONS) {
        IAM_LOGE("max connections reached (%{public}zu), reject: %{public}s", connections_.size(),
            connectionName.c_str());
        return false;
    }

    auto socketId = GetSoftBusAdapter().CreateClientSocket(connectionName, networkId);
    if (!socketId.has_value()) {
        IAM_LOGE("Create client socket failed");
        return false;
    }

    auto connection =
        std::make_shared<SoftbusConnection>(socketId.value(), connectionName, physicalDeviceKey, weak_from_this());
    if (connection == nullptr) {
        IAM_LOGE("Failed to create connection object");
        GetSoftBusAdapter().ShutdownSocket(socketId.value());
        return false;
    }
    connections_.push_back(connection);

    IAM_LOGI("OpenConnection initiated: %{public}s, socketId=%{public}d", connectionName.c_str(), socketId.value());
    return true;
}

void SoftBusConnectionManager::CloseConnection(const std::string &connectionName, const std::string &reason)
{
    auto entry = FindSocketByConnectionName(connectionName);
    if (entry == nullptr) {
        IAM_LOGE("Connection not found: %{public}s", connectionName.c_str());
        return;
    }

    RemoveSocket(entry->GetSocketId(), reason);

    IAM_LOGI("Connection closed: %{public}s", connectionName.c_str());
}

bool SoftBusConnectionManager::SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg)
{
    auto connection = FindSocketByConnectionName(connectionName);
    if (connection == nullptr) {
        IAM_LOGE("Connection not found: %{public}s", connectionName.c_str());
        return false;
    }

    return connection->SendMessage(rawMsg);
}

void SoftBusConnectionManager::HandleBind(int32_t socketId, const std::string &peerNetworkId)
{
    IAM_LOGI("HandleBind: socketId=%{public}d, peer=%{public}s", socketId, GetMaskedString(peerNetworkId).c_str());

    auto entry = FindSocketBySocketId(socketId);
    if (entry != nullptr) {
        // outbound connection
        entry->HandleOutboundConnected();
        return;
    }

    // inbound connection
    ScopeGuard guard([socketId]() { GetSoftBusAdapter().ShutdownSocket(socketId); });
    if (connections_.size() >= MAX_SOFTBUS_CONNECTIONS) {
        IAM_LOGE("max connections reached (%{public}zu), reject inbound: socketId=%{public}d", connections_.size(),
            socketId);
        return;
    }
    auto udid = GetDeviceManagerAdapter().GetUdidByNetworkId(peerNetworkId);
    ENSURE_OR_RETURN(udid.has_value() && !udid.value().empty());

    PhysicalDeviceKey physicalDeviceKey = {
        .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = udid.value(),
    };
    auto connection = std::make_shared<SoftbusConnection>(socketId, physicalDeviceKey, weak_from_this());
    ENSURE_OR_RETURN(connection != nullptr);
    connections_.push_back(connection);
    guard.Cancel();

    CheckNamingMonitor();

    IAM_LOGI("Inbound connection accepted: socketId=%{public}d", socketId);
}

void SoftBusConnectionManager::HandleError(int32_t socketId, int32_t errCode)
{
    const uint32_t UINT32_8 = 8;
    IAM_LOGE("HandleError: socketId=%{public}d, errCode=0x%{public}08x", socketId, errCode);

    auto entry = FindSocketBySocketId(socketId);
    if (entry == nullptr) {
        IAM_LOGE("Socket not found for error handling");
        return;
    }

    std::string closeReason;
    if (errCode == SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED) {
        IAM_LOGW("peer service not registered, socketId=%{public}d", socketId);
        closeReason = REASON_PEER_SERVICE_NOT_AVAILABLE;
    } else {
        std::stringstream ss;
        ss << "softbus_error_0x" << std::hex << std::setfill('0') << std::setw(UINT32_8) << errCode;
        closeReason = ss.str();
    }
    RemoveSocket(socketId, closeReason);
}

void SoftBusConnectionManager::HandleShutdown(int32_t socketId, int32_t reason)
{
    IAM_LOGI("HandleShutdown: socketId=%{public}d, reason=0x%{public}08x", socketId, reason);

    auto entry = FindSocketBySocketId(socketId);
    if (entry == nullptr) {
        RemoveSocket(socketId);
        return;
    }

    entry->MarkShutdownByPeer();
    RemoveSocket(socketId, "shutdown_reason_" + std::to_string(reason));
}

void SoftBusConnectionManager::HandleBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("HandleBytes: socketId=%{public}d, len=%{public}u", socketId, dataLen);

    if (data == nullptr || dataLen == 0) {
        IAM_LOGE("received empty data");
        return;
    }

    if (dataLen > MAX_MESSAGE_SIZE) {
        IAM_LOGE("dataLen exceeds limit: %{public}u > %{public}zu", dataLen, MAX_MESSAGE_SIZE);
        return;
    }

    std::vector<uint8_t> message(static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + dataLen);

    auto connection = FindSocketBySocketId(socketId);
    if (connection == nullptr) {
        IAM_LOGE("Connection not found for bytes handling");
        return;
    }

    if (connection->IsInbound() && connection->GetConnectionName().empty()) {
        Attributes attributes(message);
        std::string connectionName;
        if (attributes.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName) &&
            !connectionName.empty()) {
            if (FindSocketByConnectionName(connectionName) != nullptr) {
                IAM_LOGE("connectionName already exists: %{public}s, reject inbound", connectionName.c_str());
                return;
            }
            if (!IsValidInboundConnectionName(connectionName, connection->GetPhysicalDeviceKey())) {
                IAM_LOGE("Invalid inbound connectionName: %{public}s", connectionName.c_str());
                return;
            }
            IAM_LOGI("Updated connectionName from message: %{public}s", connectionName.c_str());
            connection->HandleInboundConnected(connectionName);
            CheckNamingMonitor();
        }
    }

    ENSURE_OR_RETURN(!connection->GetConnectionName().empty());
    std::string connectionName = connection->GetConnectionName();

    // Post to Resident thread for callback processing
    std::vector<RawMessageSubscription> subscribers = rawMessageSubscribers_;
    TaskRunnerManager::GetInstance().PostTaskOnResident([connectionName, message, subscribers]() mutable {
        for (const auto &sub : subscribers) {
            ENSURE_OR_CONTINUE(sub.callback != nullptr);
            sub.callback(connectionName, message);
        }
    });
}

std::unique_ptr<Subscription> SoftBusConnectionManager::SubscribeRawMessage(OnRawMessage &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    rawMessageSubscribers_.push_back({ subscriptionId, std::move(callback) });

    IAM_LOGD("raw message subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeRawMessage(subscriptionId);
    });
}

void SoftBusConnectionManager::UnsubscribeRawMessage(SubscribeId subscriptionId)
{
    auto it = std::remove_if(rawMessageSubscribers_.begin(), rawMessageSubscribers_.end(),
        [subscriptionId](const RawMessageSubscription &sub) { return sub.subscriptionId == subscriptionId; });
    if (it != rawMessageSubscribers_.end()) {
        rawMessageSubscribers_.erase(it, rawMessageSubscribers_.end());
        IAM_LOGD("raw message subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
    }
}

std::unique_ptr<Subscription> SoftBusConnectionManager::SubscribeConnectionStatus(OnConnectionStatusChange &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    connectionStatusSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGD("connection status subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeConnectionStatus(subscriptionId);
    });
}

void SoftBusConnectionManager::UnsubscribeConnectionStatus(SubscribeId subscriptionId)
{
    connectionStatusSubscribers_.erase(subscriptionId);
    IAM_LOGD("connection status subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
}

std::unique_ptr<Subscription> SoftBusConnectionManager::SubscribeIncomingConnection(OnIncomingConnection &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    incomingConnectionSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGD("incoming connection subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeIncomingConnection(subscriptionId);
    });
}

void SoftBusConnectionManager::UnsubscribeIncomingConnection(SubscribeId subscriptionId)
{
    incomingConnectionSubscribers_.erase(subscriptionId);
    IAM_LOGD("incoming connection subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
}

void SoftBusConnectionManager::NotifyIncomingConnection(const std::string &connectionName,
    const PhysicalDeviceKey &physicalDeviceKey)
{
    if (incomingConnectionSubscribers_.empty()) {
        return;
    }

    std::map<int32_t, OnIncomingConnection> subscribers = incomingConnectionSubscribers_;
    TaskRunnerManager::GetInstance().PostTaskOnResident([subscribers, connectionName, physicalDeviceKey]() mutable {
        for (const auto &pair : subscribers) {
            if (pair.second != nullptr) {
                pair.second(connectionName, physicalDeviceKey);
            }
        }
    });
}

std::shared_ptr<SoftbusConnection> SoftBusConnectionManager::FindSocketByConnectionName(
    const std::string &connectionName)
{
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [&connectionName](const std::shared_ptr<SoftbusConnection> &socket) {
            return socket != nullptr && socket->GetConnectionName() == connectionName;
        });
    return it != connections_.end() ? *it : nullptr;
}

std::shared_ptr<SoftbusConnection> SoftBusConnectionManager::FindSocketBySocketId(int32_t socketId)
{
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [&socketId](const std::shared_ptr<SoftbusConnection> &socket) {
            return socket != nullptr && socket->GetSocketId() == socketId;
        });
    return it != connections_.end() ? *it : nullptr;
}

void SoftBusConnectionManager::RemoveSocket(int32_t socketId, const std::string &closeReason)
{
    auto it = std::find_if(connections_.begin(), connections_.end(),
        [&socketId](const std::shared_ptr<SoftbusConnection> &socket) {
            return socket != nullptr && socket->GetSocketId() == socketId;
        });
    if (it != connections_.end()) {
        if (*it != nullptr) {
            (*it)->SetCloseReason(closeReason);
        }
        connections_.erase(it);
    }

    CheckNamingMonitor();
}

void SoftBusConnectionManager::CheckNamingMonitor()
{
    bool hasUnnamed = false;
    for (const auto &connection : connections_) {
        if (connection != nullptr && connection->IsInbound() && connection->GetConnectionName().empty()) {
            hasUnnamed = true;
            break;
        }
    }
    bool hasTimer = namingMonitorTimerSubscription_ != nullptr;

    if (hasUnnamed && !hasTimer) {
        namingMonitorTimerSubscription_ = RelativeTimer::GetInstance().RegisterPeriodic(
            [weakSelf = weak_from_this()]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleNamingMonitorTimer();
            },
            INBOUND_NAMING_MONITOR_INTERVAL_MS);
        ENSURE_OR_RETURN(namingMonitorTimerSubscription_ != nullptr);
        IAM_LOGI("Inbound naming monitor started");
    } else if (!hasUnnamed && hasTimer) {
        StopNamingMonitor();
    }
}

void SoftBusConnectionManager::StopNamingMonitor()
{
    if (namingMonitorTimerSubscription_ != nullptr) {
        namingMonitorTimerSubscription_.reset();
        IAM_LOGI("Inbound naming monitor stopped");
    }
}

void SoftBusConnectionManager::HandleNamingMonitorTimer()
{
    auto now = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(now.has_value());

    // Collect first, then remove: RemoveSocket mutates connections_ (and may stop
    // this very periodic timer, which is safe for Utils::Timer but must not happen
    // while we are iterating connections_).
    std::vector<int32_t> expired;
    for (const auto &connection : connections_) {
        if (connection == nullptr || !connection->IsInbound() || !connection->GetConnectionName().empty()) {
            continue;
        }
        auto ageMsOpt = SafeSub(now.value(), connection->GetAcceptTimeMs());
        if (!ageMsOpt.has_value()) {
            IAM_LOGE("Clock anomaly on inbound naming check: socketId=%{public}d", connection->GetSocketId());
            continue;
        }
        if (ageMsOpt.value() >= INBOUND_NAMING_TIMEOUT_MS) {
            IAM_LOGE(
                "Inbound connection never named within timeout, closing: socketId=%{public}d, age=%{public}" PRIu64,
                connection->GetSocketId(), ageMsOpt.value());
            expired.push_back(connection->GetSocketId());
        }
    }

    for (int32_t socketId : expired) {
        RemoveSocket(socketId, "inbound_naming_timeout");
    }
}

void SoftBusConnectionManager::HandleSoftBusServiceReady()
{
    IAM_LOGI("SoftBus service ready, start server socket");
    bool ret = StartServerSocket();
    if (!ret) {
        IAM_LOGE("StartServerSocket failed");
    }
}

void SoftBusConnectionManager::CloseAllSockets(const std::string &reason)
{
    for (auto &socket : connections_) {
        if (socket != nullptr) {
            socket->SetCloseReason(reason);
        }
    }

    if (serverSocketId_.has_value()) {
        GetSoftBusAdapter().ShutdownSocket(serverSocketId_.value());
        serverSocketId_.reset();
    }
    StopNamingMonitor();
    connections_.clear();
}

void SoftBusConnectionManager::HandleSoftBusServiceUnavailable()
{
    IAM_LOGI("SoftBus service unavailable, closing sockets");

    CloseAllSockets("softbus_down");
}

void SoftBusConnectionManager::ReportConnectionEstablished(const std::string &connectionName)
{
    if (connectionStatusSubscribers_.empty()) {
        return;
    }

    std::map<int32_t, OnConnectionStatusChange> subscribers = connectionStatusSubscribers_;
    TaskRunnerManager::GetInstance().PostTaskOnResident([subscribers, connectionName]() mutable {
        for (const auto &pair : subscribers) {
            if (pair.second != nullptr) {
                pair.second(connectionName, ConnectionStatus::CONNECTED, "established");
            }
        }
    });
}

void SoftBusConnectionManager::ReportConnectionClosed(const std::string &connectionName, const std::string &reason)
{
    if (connectionStatusSubscribers_.empty()) {
        return;
    }

    std::map<int32_t, OnConnectionStatusChange> subscribers = connectionStatusSubscribers_;
    TaskRunnerManager::GetInstance().PostTaskOnResident([subscribers, connectionName, reason]() mutable {
        for (const auto &pair : subscribers) {
            if (pair.second != nullptr) {
                pair.second(connectionName, ConnectionStatus::DISCONNECTED, reason);
            }
        }
    });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
