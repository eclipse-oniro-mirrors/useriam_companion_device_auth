/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "device_resync_scheduler.h"

#include <algorithm>
#include <new>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "common_defines.h"
#include "companion_device_auth_types.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "soft_bus_channel_common.h"
#include "subscription.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_DEVICE_RESYNC_SCHEDULER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t RESYNC_MAX_RETRY_COUNT = 5;
constexpr uint32_t RESYNC_RETRY_BASE_DELAY_MS = 1000;
constexpr uint32_t RESYNC_RETRY_MAX_DELAY_MS = 4000;
} // namespace

std::shared_ptr<DeviceResyncScheduler> DeviceResyncScheduler::Create(
    std::shared_ptr<SoftBusDeviceStatusManager> deviceStatusManager)
{
    ENSURE_OR_RETURN_VAL(deviceStatusManager != nullptr, nullptr);
    std::shared_ptr<DeviceResyncScheduler> scheduler(new (std::nothrow) DeviceResyncScheduler(deviceStatusManager));
    ENSURE_OR_RETURN_VAL(scheduler != nullptr, nullptr);
    return scheduler;
}

DeviceResyncScheduler::DeviceResyncScheduler(std::shared_ptr<SoftBusDeviceStatusManager> deviceStatusManager)
    : deviceStatusManager_(deviceStatusManager)
{
}

bool DeviceResyncScheduler::Start()
{
    unlockedActiveUserIdSubscription_ =
        GetUserIdManager().SubscribeUnlockedActiveUserId([weakSelf = weak_from_this()](UserId userId) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnActiveUserIdChanged(userId);
        });
    ENSURE_OR_RETURN_VAL(unlockedActiveUserIdSubscription_ != nullptr, false);

    deviceNameSubscription_ = GetSystemSettingsManager().SubscribeSettingsChange(SettingKey::DisplayDeviceName,
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnLocalDeviceNameChanged();
        });
    ENSURE_OR_RETURN_VAL(deviceNameSubscription_ != nullptr, false);

    deviceStatusSubscription_ = deviceStatusManager_->SubscribePhysicalDeviceStatus(
        [weakSelf = weak_from_this()](const std::vector<PhysicalDeviceStatus> &deviceStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnPhysicalDeviceStatusChanged(deviceStatusList);
        });
    ENSURE_OR_RETURN_VAL(deviceStatusSubscription_ != nullptr, false);

    IAM_LOGI("DeviceResyncScheduler started");
    return true;
}

void DeviceResyncScheduler::OnActiveUserIdChanged(UserId userId)
{
    IAM_LOGI("active user id changed to %{public}d, resync physical devices", userId);
    ResyncAllPhysicalDevices("active_user_changed");
}

void DeviceResyncScheduler::OnLocalDeviceNameChanged()
{
    IAM_LOGI("local display device name changed, resync physical devices");
    ResyncAllPhysicalDevices("device_name_changed");
}

void DeviceResyncScheduler::ResyncAllPhysicalDevices(const std::string &reason)
{
    ENSURE_OR_RETURN(deviceStatusManager_ != nullptr);
    auto devices = deviceStatusManager_->GetAllPhysicalDevices();
    IAM_LOGI("resync %{public}zu physical devices, reason %{public}s", devices.size(), reason.c_str());
    for (const auto &device : devices) {
        ResyncOneDevice(device.physicalDeviceKey, reason);
    }
}

void DeviceResyncScheduler::EnsureRetryEntry(const PhysicalDeviceKey &deviceKey, const std::string &reason)
{
    auto it = scheduledResyncs_.find(deviceKey);
    if (it != scheduledResyncs_.end()) {
        it->second.reason = reason;
        return;
    }
    BackoffRetryTimer::Config config { .baseDelayMs = RESYNC_RETRY_BASE_DELAY_MS,
        .maxDelayMs = RESYNC_RETRY_MAX_DELAY_MS,
        .maxRetryCount = RESYNC_MAX_RETRY_COUNT };
    auto timer = std::make_unique<BackoffRetryTimer>(config, [weakSelf = weak_from_this(), deviceKey]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnRetryTimerFired(deviceKey);
    });
    scheduledResyncs_.emplace(deviceKey, ResyncEntry { std::move(timer), reason });
}

void DeviceResyncScheduler::ResyncOneDevice(const PhysicalDeviceKey &deviceKey, const std::string &reason)
{
    IAM_LOGI("resync device %{public}s, reason %{public}s", GET_MASKED_STR_CSTR(deviceKey.deviceId), reason.c_str());
    EnsureRetryEntry(deviceKey, reason);

    auto it = scheduledResyncs_.find(deviceKey);
    ENSURE_OR_RETURN(it != scheduledResyncs_.end());
    it->second.timer->ResetBackoff();
    DoResyncOneDevice(deviceKey);
}

void DeviceResyncScheduler::DoResyncOneDevice(const PhysicalDeviceKey &deviceKey)
{
    auto it = scheduledResyncs_.find(deviceKey);
    ENSURE_OR_RETURN(it != scheduledResyncs_.end());

    if (it->second.isResyncInProgress) {
        IAM_LOGI("device %{public}s already resyncing, coalesce", GET_MASKED_STR_CSTR(deviceKey.deviceId));
        return;
    }

    it->second.isResyncInProgress = true;
    uint64_t attemptId = GetMiscManager().GetNextGlobalId();
    it->second.inProgressAttemptId = attemptId;
    const std::string &reason = it->second.reason;

    auto onComplete = [weakSelf = weak_from_this(), deviceKey, attemptId](ResultCode result) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->HandleResyncComplete(deviceKey, attemptId, result);
    };
    auto request = GetRequestFactory().CreateCompanionRequestResyncRequest(deviceKey, std::move(onComplete));
    if (request == nullptr) {
        IAM_LOGE("failed to create resync request for device %{public}s", GET_MASKED_STR_CSTR(deviceKey.deviceId));
        HandleResyncFailure(deviceKey);
        return;
    }
    if (!GetRequestManager().Start(request)) {
        IAM_LOGE("failed to start resync request for device %{public}s, reason %{public}s",
            GET_MASKED_STR_CSTR(deviceKey.deviceId), reason.c_str());
        HandleResyncFailure(deviceKey);
    }
}

void DeviceResyncScheduler::OnRetryTimerFired(const PhysicalDeviceKey &deviceKey)
{
    DoResyncOneDevice(deviceKey);
}

void DeviceResyncScheduler::HandleResyncFailure(const PhysicalDeviceKey &deviceKey)
{
    auto it = scheduledResyncs_.find(deviceKey);
    if (it == scheduledResyncs_.end()) {
        return;
    }
    // The in-progress slot is free again; a retry (if any) reuses the same entry.
    it->second.isResyncInProgress = false;

    if (!deviceStatusManager_->GetPhysicalDeviceStatus(deviceKey).has_value()) {
        IAM_LOGI("device %{public}s offline, skip resync retry", GET_MASKED_STR_CSTR(deviceKey.deviceId));
        scheduledResyncs_.erase(it);
        return;
    }
    if (!it->second.timer->OnFailure()) {
        IAM_LOGE("resync retry exhausted for device %{public}s, reason %{public}s",
            GET_MASKED_STR_CSTR(deviceKey.deviceId), it->second.reason.c_str());
        scheduledResyncs_.erase(it);
    }
}

void DeviceResyncScheduler::HandleResyncComplete(const PhysicalDeviceKey &deviceKey, uint64_t attemptId,
    ResultCode result)
{
    auto it = scheduledResyncs_.find(deviceKey);
    if (it == scheduledResyncs_.end()) {
        IAM_LOGI("no retry entry for device %{public}s, drop stale completion",
            GET_MASKED_STR_CSTR(deviceKey.deviceId));
        return;
    }

    if (it->second.inProgressAttemptId != attemptId) {
        IAM_LOGI("drop stale resync completion for device %{public}s", GET_MASKED_STR_CSTR(deviceKey.deviceId));
        return;
    }

    // This completion is for the current in-progress request: the slot is free again.
    it->second.isResyncInProgress = false;

    if (result == ResultCode::SUCCESS) {
        scheduledResyncs_.erase(it);
        return;
    }
    // Any non-success result (failure, preemption/cancel, timeout) is retried while the device stays
    // online; an offline device is dropped instead of being hammered.
    HandleResyncFailure(deviceKey);
}

void DeviceResyncScheduler::OnPhysicalDeviceStatusChanged(const std::vector<PhysicalDeviceStatus> &deviceStatusList)
{
    std::set<PhysicalDeviceKey> currentOnline;
    for (const auto &status : deviceStatusList) {
        currentOnline.insert(status.physicalDeviceKey);
    }

    for (const auto &key : currentOnline) {
        if (prevOnlineDevices_.find(key) == prevOnlineDevices_.end()) {
            IAM_LOGI("device %{public}s newly online, resync", GET_MASKED_STR_CSTR(key.deviceId));
            ResyncOneDevice(key, "device_online");
        }
    }

    for (auto it = scheduledResyncs_.begin(); it != scheduledResyncs_.end();) {
        if (currentOnline.find(it->first) == currentOnline.end()) {
            IAM_LOGI("device %{public}s offline, cancel pending resync retry", GET_MASKED_STR_CSTR(it->first.deviceId));
            it = scheduledResyncs_.erase(it);
        } else {
            ++it;
        }
    }

    prevOnlineDevices_ = std::move(currentOnline);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
