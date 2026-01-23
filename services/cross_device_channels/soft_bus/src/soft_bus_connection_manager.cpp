/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "soft_bus_connection_manager.h"

#include <algorithm>
#include <cinttypes>
#include <utility>

#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "cda_attributes.h"
#include "sa_status_listener.h"
#include "scope_guard.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "soft_bus_adapter_manager.h"
#include "soft_bus_channel_common.h"
#include "soft_bus_socket.h"
#include "softbus_error_code.h"
#include "subscription.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr const char *SOFTBUS_SA_NAME = "SoftBusServer";
} // namespace

std::shared_ptr<SoftBusConnectionManager> SoftBusConnectionManager::Create()
{
    auto adapter = std::shared_ptr<SoftBusConnectionManager>(new (std::nothrow) SoftBusConnectionManager());
    ENSURE_OR_RETURN_VAL(adapter != nullptr, nullptr);
    bool ret = adapter->Initialize();
    if (!ret) {
        IAM_LOGE("Initialize SoftBusConnectionManager failed");
        return nullptr;
    }

    return adapter;
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

    auto socketId = GetSoftBusAdapter().CreateClientSocket(connectionName, networkId);
    if (!socketId.has_value()) {
        IAM_LOGE("Create client socket failed");
        return false;
    }

    auto socket =
        std::make_shared<SoftBusSocket>(socketId.value(), connectionName, physicalDeviceKey, weak_from_this());
    if (socket == nullptr) {
        IAM_LOGE("Failed to create socket object");
        GetSoftBusAdapter().ShutdownSocket(socketId.value());
        return false;
    }
    sockets_.push_back(socket);

    IAM_LOGI("OpenConnection initiated: %{public}s, socketId=%{public}d", connectionName.c_str(), socketId.value());
    return true;
}

void SoftBusConnectionManager::CloseConnection(const std::string &connectionName)
{
    auto entry = FindSocketByConnectionName(connectionName);
    if (entry == nullptr) {
        IAM_LOGW("Connection not found: %{public}s", connectionName.c_str());
        return;
    }

    RemoveSocket(entry->GetSocketId(), "active-close");

    IAM_LOGI("Connection closed: %{public}s", connectionName.c_str());
}

bool SoftBusConnectionManager::SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg)
{
    auto entry = FindSocketByConnectionName(connectionName);
    if (entry == nullptr || !entry->IsConnected()) {
        IAM_LOGE("Connection not found or not connected: %{public}s", connectionName.c_str());
        return false;
    }

    if (!GetSoftBusAdapter().SendBytes(entry->GetSocketId(), rawMsg)) {
        IAM_LOGE("SendBytes failed");
        return false;
    }

    return true;
}

void SoftBusConnectionManager::HandleBind(int32_t socketId, const std::string &peerNetworkId)
{
    IAM_LOGI("HandleBind: socketId=%{public}d, peer=%{public}s", socketId, peerNetworkId.c_str());

    auto entry = FindSocketBySocketId(socketId);
    if (entry != nullptr) {
        // outbound connection
        entry->HandleOutboundConnected();
        return;
    }

    // inbound connection
    ScopeGuard guard([socketId]() { GetSoftBusAdapter().ShutdownSocket(socketId); });
    auto udidResult = GetDeviceManagerAdapter().GetUdidByNetworkId(peerNetworkId);
    ENSURE_OR_RETURN(udidResult.has_value());
    std::string udid = udidResult.value();
    ENSURE_OR_RETURN(!udid.empty());

    PhysicalDeviceKey physicalDeviceKey = {
        .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = udid,
    };
    auto socket = std::make_shared<SoftBusSocket>(socketId, physicalDeviceKey, weak_from_this());
    if (socket == nullptr) {
        IAM_LOGE("Failed to create socket object for inbound connection");
        return;
    }
    sockets_.push_back(socket);
    guard.Cancel();

    IAM_LOGI("Inbound connection accepted: socketId=%{public}d", socketId);
}

void SoftBusConnectionManager::HandleError(int32_t socketId, int32_t errCode)
{
    IAM_LOGE("HandleError: socketId=%{public}d, errCode=%{public}d", socketId, errCode);

    auto entry = FindSocketBySocketId(socketId);
    if (entry == nullptr) {
        IAM_LOGW("Socket not found for error handling");
        return;
    }

    RemoveSocket(socketId, "error_" + std::to_string(errCode));
}

void SoftBusConnectionManager::HandleShutdown(int32_t socketId, int32_t reason)
{
    IAM_LOGI("HandleShutdown: socketId=%{public}d, reason=%{public}d", socketId, reason);

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

    auto socket = FindSocketBySocketId(socketId);
    ENSURE_OR_RETURN(socket != nullptr);

    if (data == nullptr || dataLen == 0) {
        IAM_LOGE("received empty data");
        return;
    }

    std::vector<uint8_t> message(static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + dataLen);

    if (socket->IsInbound() && socket->GetConnectionName().empty()) {
        Attributes attributes(message);
        std::string connectionName;
        if (attributes.GetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName) &&
            !connectionName.empty()) {
            IAM_LOGI("Updated connectionName from message: %{public}s", connectionName.c_str());
            socket->HandleInboundConnected(connectionName);
        }
    }

    std::string connectionName = socket->GetConnectionName();
    std::vector<RawMessageSubscription> subscribers = rawMessageSubscribers_;
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [subscribers, connectionName, message = std::move(message)]() mutable {
            for (const auto &sub : subscribers) {
                if (sub.callback != nullptr && (sub.connectionName.empty() || sub.connectionName == connectionName)) {
                    sub.callback(connectionName, message);
                }
            }
        });
}

std::unique_ptr<Subscription> SoftBusConnectionManager::SubscribeRawMessage(OnRawMessage &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    rawMessageSubscribers_.push_back({ subscriptionId, "", std::move(callback) });

    IAM_LOGD("raw message subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
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
        rawMessageSubscribers_.erase(it);
        IAM_LOGD("raw message subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
    }
}

std::unique_ptr<Subscription> SoftBusConnectionManager::SubscribeConnectionStatus(OnConnectionStatusChange &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);

    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    connectionStatusSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGD("connection status subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
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

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
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

std::shared_ptr<SoftBusSocket> SoftBusConnectionManager::FindSocketByConnectionName(const std::string &connectionName)
{
    auto it =
        std::find_if(sockets_.begin(), sockets_.end(), [&connectionName](const std::shared_ptr<SoftBusSocket> &socket) {
            return socket != nullptr && socket->GetConnectionName() == connectionName;
        });
    return it != sockets_.end() && *it != nullptr ? *it : nullptr;
}

std::shared_ptr<SoftBusSocket> SoftBusConnectionManager::FindSocketBySocketId(int32_t socketId)
{
    auto it = std::find_if(sockets_.begin(), sockets_.end(), [&socketId](const std::shared_ptr<SoftBusSocket> &socket) {
        return socket != nullptr && socket->GetSocketId() == socketId;
    });
    return it != sockets_.end() && *it != nullptr ? *it : nullptr;
}

void SoftBusConnectionManager::RemoveSocket(int32_t socketId, const std::string &closeReason)
{
    auto it = std::find_if(sockets_.begin(), sockets_.end(), [&socketId](const std::shared_ptr<SoftBusSocket> &socket) {
        return socket != nullptr && socket->GetSocketId() == socketId;
    });
    if (it != sockets_.end()) {
        if (*it != nullptr) {
            (*it)->SetCloseReason(closeReason);
        }
        sockets_.erase(it);
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
    for (auto &socket : sockets_) {
        if (socket != nullptr) {
            socket->SetCloseReason(reason);
        }
    }

    if (serverSocketId_.has_value()) {
        GetSoftBusAdapter().ShutdownSocket(serverSocketId_.value());
        serverSocketId_.reset();
    }
    sockets_.clear();
}

void SoftBusConnectionManager::HandleSoftBusServiceUnavailable()
{
    IAM_LOGI("SoftBus service unavailable, closing sockets");

    CloseAllSockets("softbus down");
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
