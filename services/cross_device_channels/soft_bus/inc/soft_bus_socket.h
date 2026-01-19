/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef SOFT_BUS_SOCKET_H
#define SOFT_BUS_SOCKET_H

#include <memory>
#include <string>

#include "nocopyable.h"

#include "cross_device_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SoftBusConnectionManager;

class SoftBusSocket : public NoCopyable {
public:
    SoftBusSocket(int32_t socketId, const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey,
        std::weak_ptr<SoftBusConnectionManager> adapter);
    SoftBusSocket(int32_t socketId, const PhysicalDeviceKey &physicalDeviceKey,
        std::weak_ptr<SoftBusConnectionManager> adapter);
    ~SoftBusSocket();

    int32_t GetSocketId() const
    {
        return socketId_;
    }
    const std::string &GetConnectionName() const
    {
        return connectionName_;
    }
    const PhysicalDeviceKey &GetPhysicalDeviceKey() const
    {
        return physicalDeviceKey_;
    }
    bool IsConnected() const
    {
        return isConnected_;
    }
    bool IsInbound() const
    {
        return isInbound_;
    }

    void SetCloseReason(const std::string &reason);
    void SetConnectionName(const std::string &connectionName);
    void HandleOutboundConnected();
    void HandleInboundConnected(const std::string &connectionName);
    void MarkShutdownByPeer();

private:
    void Cleanup();
    void NotifyConnectionEstablished();
    void NotifyConnectionClosed();
    void NotifyIncomingConnection();

    int32_t socketId_;
    std::string connectionName_;
    PhysicalDeviceKey physicalDeviceKey_;
    bool isConnected_;
    bool isInbound_;
    bool isShutdownByPeer_;
    std::string closeReason_;
    std::weak_ptr<SoftBusConnectionManager> adapter_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // SOFT_BUS_SOCKET_H
