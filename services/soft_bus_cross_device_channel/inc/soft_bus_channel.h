/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef SOFTBUS_CHANNEL_H
#define SOFTBUS_CHANNEL_H

#include <memory>
#include <string>

#include "nocopyable.h"

#include "cross_device_common.h"
#include "icross_device_channel.h"
#include "misc_manager.h"
#include "soft_bus_channel_common.h"
#include "soft_bus_connection_manager.h"
#include "soft_bus_device_status_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SoftBusChannel : public ICrossDeviceChannel, public NoCopyable {
public:
    static std::shared_ptr<SoftBusChannel> Create();

    ~SoftBusChannel() override = default;

    bool Start() override;

    ChannelId GetChannelId() const override;
    PhysicalDeviceKey GetLocalPhysicalDeviceKey() const override;

    bool OpenConnection(const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey) override;
    void CloseConnection(const std::string &connectionName) override;
    bool SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg) override;

    std::unique_ptr<Subscription> SubscribePhysicalDeviceStatus(OnPhysicalDeviceStatusChange &&callback) override;
    std::unique_ptr<Subscription> SubscribeRawMessage(OnRawMessage &&callback) override;
    std::unique_ptr<Subscription> SubscribeConnectionStatus(OnConnectionStatusChange &&callback) override;
    std::unique_ptr<Subscription> SubscribeIncomingConnection(OnIncomingConnection &&callback) override;
    std::vector<PhysicalDeviceStatus> GetAllPhysicalDevices() const override;

    bool GetAuthMaintainActive() const override;
    std::unique_ptr<Subscription> SubscribeAuthMaintainActive(OnAuthMaintainActiveChange &&callback) override;

    SecureProtocolId GetcompanionSecureProtocolId() const override;

    bool CheckOperationIntent(const DeviceKey &deviceKey, uint32_t tokenId,
        OnCheckOperationIntentResult &&resultCallback) override;

private:
    SoftBusChannel();
    bool Initialize();

    std::shared_ptr<SoftBusConnectionManager> connectionManager_;
    std::shared_ptr<SoftBusDeviceStatusManager> deviceStatusManager_;
    bool started_ { false };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // SOFTBUS_CHANNEL_H
