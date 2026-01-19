/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef SOFT_BUS_DEVICE_STATUS_MANAGER_H
#define SOFT_BUS_DEVICE_STATUS_MANAGER_H

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "device_manager.h"
#include "nocopyable.h"

#include "cross_device_comm_manager.h"
#include "icross_device_channel.h"
#include "incoming_message_handler_registry.h"
#include "misc_manager.h"
#include "sa_status_listener.h"
#include "soft_bus_channel_common.h"
#include "subscription.h"
#include "system_param_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SoftBusDeviceStatusManager : public std::enable_shared_from_this<SoftBusDeviceStatusManager>, public NoCopyable {
public:
    static std::shared_ptr<SoftBusDeviceStatusManager> Create();

    ~SoftBusDeviceStatusManager();

    bool Start();
    std::unique_ptr<Subscription> SubscribePhysicalDeviceStatus(OnPhysicalDeviceStatusChange &&callback);
    std::unique_ptr<Subscription> SubscribeAuthMaintainActive(OnAuthMaintainActiveChange &&callback);
    std::optional<PhysicalDeviceStatus> GetPhysicalDeviceStatus(const PhysicalDeviceKey &key);
    std::vector<PhysicalDeviceStatus> GetAllPhysicalDevices() const;
    void RefreshDeviceStatus();
    void HandleLocalIsAuthMaintainActiveChange(bool isAuthMaintainActive);
    bool GetAuthMaintainActive() const;
    std::optional<PhysicalDeviceKey> GetLocalPhysicalDeviceKey() const;

private:
    static std::string DeviceTypeIdToString(DistributedHardware::DmDeviceType deviceTypeId);
    static std::string GenerateDeviceModelInfo(DistributedHardware::DmDeviceType deviceTypeId);
    static bool IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType deviceTypeId);
    SoftBusDeviceStatusManager();
    bool Initialize();

    void HandleDeviceManagerServiceReady();
    void HandleDeviceManagerServiceUnavailable();

    bool InitDeviceManager();
    void UnInitDeviceManager();
    bool RegisterDeviceStatusCallback();
    void UnregisterDeviceStatusCallback();

    bool QueryTrustedDevices(std::vector<DistributedHardware::DmDeviceInfo> &deviceList);
    bool ConvertToPhysicalDevices(const std::vector<DistributedHardware::DmDeviceInfo> &deviceList,
        std::vector<PhysicalDeviceStatus> &statuses);
    void NotifyDeviceStatusChange();
    void NotifyAuthMaintainActiveChange();
    void UnsubscribePhysicalDeviceStatus(SubscribeId subscriptionId);
    void UnsubscribeAuthMaintainActive(SubscribeId subscriptionId);

    std::unique_ptr<SaStatusListener> saStatusListener_;
    std::shared_ptr<DistributedHardware::DmInitCallback> dmInitCallback_;
    std::shared_ptr<DistributedHardware::DeviceStatusCallback> dsCallback_;
    std::map<int32_t, OnPhysicalDeviceStatusChange> physicalDeviceStatusSubscribers_;
    std::map<int32_t, OnAuthMaintainActiveChange> authMaintainActiveSubscribers_;
    std::unique_ptr<Subscription> systemParamSubscription_;

    bool dmInitialized_ { false };
    bool isLocalAuthMaintainActive_ { false };
    std::vector<PhysicalDeviceStatus> physicalDeviceStatus_;
    bool started_ { false };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // SOFT_BUS_DEVICE_STATUS_MANAGER_H
