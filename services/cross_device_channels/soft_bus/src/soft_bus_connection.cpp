/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "soft_bus_connection.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "soft_bus_adapter_manager.h"
#include "soft_bus_connection_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr int32_t INVALID_SOCKET_ID = -1;
} // namespace

SoftbusConnection::SoftbusConnection(int32_t socketId, const std::string &connectionName,
    const PhysicalDeviceKey &physicalDeviceKey, std::weak_ptr<SoftBusConnectionManager> manager)
    : socketId_(socketId),
      connectionName_(connectionName),
      physicalDeviceKey_(physicalDeviceKey),
      isConnected_(false),
      isInbound_(false),
      isShutdownByPeer_(false),
      closeReason_(""),
      manager_(std::move(manager))
{
}

SoftbusConnection::SoftbusConnection(int32_t socketId, const PhysicalDeviceKey &physicalDeviceKey,
    std::weak_ptr<SoftBusConnectionManager> manager)
    : socketId_(socketId),
      connectionName_(""),
      physicalDeviceKey_(physicalDeviceKey),
      isConnected_(false),
      isInbound_(true),
      isShutdownByPeer_(false),
      closeReason_(""),
      manager_(std::move(manager))
{
}

SoftbusConnection::~SoftbusConnection()
{
    Cleanup();
}

void SoftbusConnection::SetCloseReason(const std::string &reason)
{
    closeReason_ = reason;
}

void SoftbusConnection::SetConnectionName(const std::string &connectionName)
{
    connectionName_ = connectionName;
}

void SoftbusConnection::HandleOutboundConnected()
{
    if (isConnected_ == true) {
        return;
    }
    isConnected_ = true;
    NotifyConnectionEstablished();
}

void SoftbusConnection::HandleInboundConnected(const std::string &connectionName)
{
    if (isConnected_ == true) {
        return;
    }

    if (connectionName_.empty() && !connectionName.empty()) {
        connectionName_ = connectionName;
    }

    isConnected_ = true;
    NotifyIncomingConnection();
}

void SoftbusConnection::MarkShutdownByPeer()
{
    isShutdownByPeer_ = true;
}

bool SoftbusConnection::SendMessage(const std::vector<uint8_t> &data)
{
    if (!isConnected_) {
        IAM_LOGE("Connection not established: %{public}s", connectionName_.c_str());
        return false;
    }

    if (!GetSoftBusAdapter().SendBytes(socketId_, data)) {
        IAM_LOGE("SendBytes failed: %{public}s", connectionName_.c_str());
        return false;
    }

    return true;
}

void SoftbusConnection::Cleanup()
{
    if (socketId_ > INVALID_SOCKET_ID) {
        if (!isShutdownByPeer_) {
            ::Shutdown(socketId_);
        }
        socketId_ = INVALID_SOCKET_ID;
    }

    NotifyConnectionClosed();
}

void SoftbusConnection::NotifyConnectionEstablished()
{
    ENSURE_OR_RETURN(!connectionName_.empty());

    auto manager = manager_.lock();
    ENSURE_OR_RETURN(manager != nullptr);

    manager->ReportConnectionEstablished(connectionName_);
}

void SoftbusConnection::NotifyConnectionClosed()
{
    ENSURE_OR_RETURN(!connectionName_.empty());

    auto manager = manager_.lock();
    ENSURE_OR_RETURN(manager != nullptr);

    manager->ReportConnectionClosed(connectionName_, closeReason_);
}

void SoftbusConnection::NotifyIncomingConnection()
{
    ENSURE_OR_RETURN(isInbound_);
    ENSURE_OR_RETURN(!connectionName_.empty());

    auto manager = manager_.lock();
    ENSURE_OR_RETURN(manager != nullptr);

    manager->NotifyIncomingConnection(connectionName_, physicalDeviceKey_);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
