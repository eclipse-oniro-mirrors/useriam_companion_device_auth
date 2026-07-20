/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef DEVICE_RESYNC_SCHEDULER_H
#define DEVICE_RESYNC_SCHEDULER_H

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>

#include "nocopyable.h"

#include "backoff_retry_timer.h"
#include "cross_device_common.h"
#include "soft_bus_device_status_manager.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class DeviceResyncScheduler : public std::enable_shared_from_this<DeviceResyncScheduler>, public NoCopyable {
public:
    static std::shared_ptr<DeviceResyncScheduler> Create(
        std::shared_ptr<SoftBusDeviceStatusManager> deviceStatusManager);

    ~DeviceResyncScheduler() = default;

    bool Start();
    void ResyncAllPhysicalDevices(const std::string &reason);

private:
    explicit DeviceResyncScheduler(std::shared_ptr<SoftBusDeviceStatusManager> deviceStatusManager);

    void OnActiveUserIdChanged(UserId userId);
    void OnLocalDeviceNameChanged();
    void ResyncOneDevice(const PhysicalDeviceKey &deviceKey, const std::string &reason);
    void DoResyncOneDevice(const PhysicalDeviceKey &deviceKey);
    void EnsureRetryEntry(const PhysicalDeviceKey &deviceKey, const std::string &reason);
    void OnRetryTimerFired(const PhysicalDeviceKey &deviceKey);
    void HandleResyncComplete(const PhysicalDeviceKey &deviceKey, uint64_t attemptId, ResultCode result);
    void HandleResyncFailure(const PhysicalDeviceKey &deviceKey);
    void OnPhysicalDeviceStatusChanged(const std::vector<PhysicalDeviceStatus> &deviceStatusList);

    struct ResyncEntry {
        std::unique_ptr<BackoffRetryTimer> timer;
        std::string reason;
        bool isResyncInProgress { false };
        uint64_t inProgressAttemptId { 0 };
    };

    std::shared_ptr<SoftBusDeviceStatusManager> deviceStatusManager_;
    std::map<PhysicalDeviceKey, ResyncEntry> scheduledResyncs_;
    std::set<PhysicalDeviceKey> prevOnlineDevices_;
    std::unique_ptr<Subscription> unlockedActiveUserIdSubscription_;
    std::unique_ptr<Subscription> deviceNameSubscription_;
    std::unique_ptr<Subscription> deviceStatusSubscription_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // DEVICE_RESYNC_SCHEDULER_H
