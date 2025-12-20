/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef SOFT_BUS_CONNECTION_MANAGER_H
#define SOFT_BUS_CONNECTION_MANAGER_H

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "socket.h"

#include "icross_device_channel.h"
#include "sa_status_listener.h"
#include "singleton_manager.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class SoftBusSocket;

class SoftBusConnectionManager : public std::enable_shared_from_this<SoftBusConnectionManager> {
public:
    static std::shared_ptr<SoftBusConnectionManager> Create();
    ~SoftBusConnectionManager();

    bool Start();

    bool OpenConnection(const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey,
        const std::string &networkId);

    void CloseConnection(const std::string &connectionName);

    bool SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg);

    void HandleBind(int32_t socketId, const std::string &peerNetworkId);
    void HandleError(int32_t socketId, int32_t errCode);
    void HandleShutdown(int32_t socketId, int32_t reason);
    void HandleBytes(int32_t socketId, const void *data, uint32_t dataLen);

    std::unique_ptr<Subscription> SubscribeRawMessage(OnRawMessage &&callback);
    std::unique_ptr<Subscription> SubscribeConnectionStatus(OnConnectionStatusChange &&callback);
    std::unique_ptr<Subscription> SubscribeIncomingConnection(OnIncomingConnection &&callback);

    void ReportConnectionEstablished(const std::string &connectionName);
    void ReportConnectionClosed(const std::string &connectionName, const std::string &reason);

private:
    SoftBusConnectionManager();
    bool Initialize();
    bool StartServerSocket();

    bool SendBytesWithRetry(int32_t socketId, const std::vector<uint8_t> &data);

    std::shared_ptr<SoftBusSocket> FindSocketByConnectionName(const std::string &connectionName);
    std::shared_ptr<SoftBusSocket> FindSocketBySocketId(int32_t socketId);
    void RemoveSocket(int32_t socketId, const std::string &closeReason = "");
    void CloseAllSockets(const std::string &reason = "");
    void HandleSoftBusServiceReady();
    void HandleSoftBusServiceUnavailable();
    void UnsubscribeRawMessage(int32_t subscriptionId);
    void UnsubscribeConnectionStatus(int32_t subscriptionId);
    void UnsubscribeIncomingConnection(int32_t subscriptionId);
    void NotifyIncomingConnection(const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey);

    friend class SoftBusSocket;

    std::optional<int32_t> serverSocketId_;
    std::vector<std::shared_ptr<SoftBusSocket>> sockets_;

    std::map<int32_t, OnRawMessage> rawMessageSubscribers_;
    std::map<int32_t, OnConnectionStatusChange> connectionStatusSubscribers_;
    std::map<int32_t, OnIncomingConnection> incomingConnectionSubscribers_;
    std::unique_ptr<SaStatusListener> saStatusListener_;
    bool started_ { false };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // SOFT_BUS_CONNECTION_MANAGER_H
