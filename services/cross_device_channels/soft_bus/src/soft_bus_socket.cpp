/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "soft_bus_socket.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "soft_bus_connection_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr int32_t INVALID_SOCKET_ID = -1;
} // namespace

SoftBusSocket::SoftBusSocket(int32_t socketId, const std::string &connectionName,
    const PhysicalDeviceKey &physicalDeviceKey, std::weak_ptr<SoftBusConnectionManager> adapter)
    : socketId_(socketId),
      connectionName_(connectionName),
      physicalDeviceKey_(physicalDeviceKey),
      isConnected_(false),
      isInbound_(false),
      isShutdownByPeer_(false),
      closeReason_(""),
      adapter_(std::move(adapter))
{
}

SoftBusSocket::SoftBusSocket(int32_t socketId, const PhysicalDeviceKey &physicalDeviceKey,
    std::weak_ptr<SoftBusConnectionManager> adapter)
    : socketId_(socketId),
      connectionName_(""),
      physicalDeviceKey_(physicalDeviceKey),
      isConnected_(false),
      isInbound_(true),
      isShutdownByPeer_(false),
      closeReason_(""),
      adapter_(std::move(adapter))
{
}

SoftBusSocket::~SoftBusSocket()
{
    Cleanup();
}

void SoftBusSocket::SetCloseReason(const std::string &reason)
{
    closeReason_ = reason;
}

void SoftBusSocket::SetConnectionName(const std::string &connectionName)
{
    connectionName_ = connectionName;
}

void SoftBusSocket::HandleOutboundConnected()
{
    if (isConnected_ == true) {
        return;
    }
    isConnected_ = true;
    NotifyConnectionEstablished();
}

void SoftBusSocket::HandleInboundConnected(const std::string &connectionName)
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

void SoftBusSocket::MarkShutdownByPeer()
{
    isShutdownByPeer_ = true;
}

void SoftBusSocket::Cleanup()
{
    if (socketId_ > INVALID_SOCKET_ID) {
        if (!isShutdownByPeer_) {
            ::Shutdown(socketId_);
        }
        socketId_ = INVALID_SOCKET_ID;
    }

    NotifyConnectionClosed();
}

void SoftBusSocket::NotifyConnectionEstablished()
{
    ENSURE_OR_RETURN(!connectionName_.empty());

    auto adapter = adapter_.lock();
    ENSURE_OR_RETURN(adapter != nullptr);

    adapter->ReportConnectionEstablished(connectionName_);
}

void SoftBusSocket::NotifyConnectionClosed()
{
    ENSURE_OR_RETURN(!connectionName_.empty());

    auto adapter = adapter_.lock();
    ENSURE_OR_RETURN(adapter != nullptr);

    adapter->ReportConnectionClosed(connectionName_, closeReason_);
}

void SoftBusSocket::NotifyIncomingConnection()
{
    ENSURE_OR_RETURN(isInbound_);
    ENSURE_OR_RETURN(!connectionName_.empty());

    auto adapter = adapter_.lock();
    ENSURE_OR_RETURN(adapter != nullptr);

    adapter->NotifyIncomingConnection(connectionName_, physicalDeviceKey_);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
