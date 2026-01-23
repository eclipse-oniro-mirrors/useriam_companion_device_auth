/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "device_status_manager.h"

#include <algorithm>
#include <cinttypes>
#include <memory>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "adapter_manager.h"
#include "channel_manager.h"
#include "connection_manager.h"
#include "host_sync_device_status_request.h"
#include "scope_guard.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "time_keeper.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<DeviceStatusManager> DeviceStatusManager::Create(std::shared_ptr<ConnectionManager> connectionMgr,
    std::shared_ptr<ChannelManager> channelMgr, std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr)
{
    auto manager = std::shared_ptr<DeviceStatusManager>(
        new (std::nothrow) DeviceStatusManager(connectionMgr, channelMgr, localDeviceStatusMgr));
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);

    if (!manager->Initialize()) {
        IAM_LOGE("failed to initialize DeviceStatusManager");
        return nullptr;
    }

    return manager;
}

DeviceStatusManager::DeviceStatusManager(std::shared_ptr<ConnectionManager> connectionMgr,
    std::shared_ptr<ChannelManager> channelMgr, std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr)
    : connectionMgr_(connectionMgr),
      channelMgr_(channelMgr),
      localDeviceStatusMgr_(localDeviceStatusMgr)
{
}

DeviceStatusManager::~DeviceStatusManager()
{
    StopPeriodicSync();
}

bool DeviceStatusManager::Initialize()
{
    ENSURE_OR_RETURN_VAL(connectionMgr_ != nullptr, false);
    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, false);
    ENSURE_OR_RETURN_VAL(localDeviceStatusMgr_ != nullptr, false);

    auto weakSelf = weak_from_this();
    for (const auto &channel : channelMgr_->GetAllChannels()) {
        ChannelId channelId = channel->GetChannelId();
        auto subscription = channel->SubscribePhysicalDeviceStatus(
            [weakSelf, channelId](const std::vector<PhysicalDeviceStatus> &statusList) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleChannelDeviceStatusChange(channelId, statusList);
            });
        if (subscription != nullptr) {
            channelSubscriptions_[channelId] = std::move(subscription);
        }
    }

    activeUserIdSubscription_ = GetUserIdManager().SubscribeActiveUserId([weakSelf](UserId userId) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->HandleUserIdChange(userId);
    });
    ENSURE_OR_RETURN_VAL(activeUserIdSubscription_ != nullptr, false);

    activeUserId_ = GetUserIdManager().GetActiveUserId();

    return true;
}

std::optional<DeviceStatus> DeviceStatusManager::GetDeviceStatus(const DeviceKey &deviceKey)
{
    ENSURE_OR_RETURN_VAL(deviceKey.deviceUserId == activeUserId_, std::nullopt);

    PhysicalDeviceKey physicalKey {};
    physicalKey.idType = deviceKey.idType;
    physicalKey.deviceId = deviceKey.deviceId;

    auto it = deviceStatusMap_.find(physicalKey);
    if (it != deviceStatusMap_.end() && it->second.isSynced) {
        return it->second.BuildDeviceStatus(activeUserId_);
    }

    return std::nullopt;
}

std::optional<ChannelId> DeviceStatusManager::GetChannelIdByDeviceKey(const DeviceKey &deviceKey)
{
    ENSURE_OR_RETURN_VAL(deviceKey.deviceUserId == activeUserId_, std::nullopt);

    PhysicalDeviceKey physicalKey {};
    physicalKey.idType = deviceKey.idType;
    physicalKey.deviceId = deviceKey.deviceId;

    auto it = deviceStatusMap_.find(physicalKey);
    ENSURE_OR_RETURN_VAL(it != deviceStatusMap_.end(), std::nullopt);
    ENSURE_OR_RETURN_VAL(it->second.channelId != ChannelId::INVALID, std::nullopt);
    return it->second.channelId;
}

std::vector<DeviceStatus> DeviceStatusManager::GetAllDeviceStatus()
{
    std::vector<DeviceStatus> result;

    for (const auto &pair : deviceStatusMap_) {
        if (pair.second.isSynced) {
            result.push_back(pair.second.BuildDeviceStatus(activeUserId_));
        }
    }

    return result;
}

std::unique_ptr<Subscription> DeviceStatusManager::SubscribeDeviceStatus(OnDeviceStatusChange &&callback)
{
    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    DeviceStatusSubscriptionInfo info {};
    info.subscriptionId = subscriptionId;
    info.deviceKey = std::nullopt;
    info.callback = std::move(callback);
    subscriptions_.push_back(info);

    IAM_LOGD("device status subscription added: id=0x%{public}016" PRIX64 " (all devices)", subscriptionId);

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeDeviceStatus(subscriptionId);
    });
}

void DeviceStatusManager::HandleSyncResult(const DeviceKey &deviceKey, int32_t resultCode,
    const SyncDeviceStatus &syncDeviceStatus)
{
    IAM_LOGI("device sync result: device=%{public}s, result=%{public}d", deviceKey.GetDesc().c_str(), resultCode);

    if (deviceKey.deviceUserId != activeUserId_) {
        IAM_LOGI("device not belong to active user, skipping");
        return;
    }

    PhysicalDeviceKey physicalKey {};
    physicalKey.idType = deviceKey.idType;
    physicalKey.deviceId = deviceKey.deviceId;

    auto it = deviceStatusMap_.find(physicalKey);
    if (it == deviceStatusMap_.end()) {
        IAM_LOGW("device not found in cache");
        return;
    }

    DeviceStatusEntry &deviceStatus = it->second;

    ScopeGuard guard([&deviceStatus]() {
        deviceStatus.isSynced = false;
        deviceStatus.isSyncInProgress = false;
    });

    if (resultCode != SUCCESS) {
        IAM_LOGE("sync failed: %{public}d", resultCode);
        return;
    }

    auto negotiatedProtocol = NegotiateProtocol(syncDeviceStatus.protocolIdList);
    ENSURE_OR_RETURN(negotiatedProtocol.has_value());
    auto negotiatedCapabilities = NegotiateCapabilities(syncDeviceStatus.capabilityList);
    ENSURE_OR_RETURN(negotiatedCapabilities.size() > 0);

    deviceStatus.deviceUserName = syncDeviceStatus.deviceUserName;
    deviceStatus.protocolId = negotiatedProtocol.value();
    deviceStatus.secureProtocolId = syncDeviceStatus.secureProtocolId;
    deviceStatus.capabilities = negotiatedCapabilities;
    deviceStatus.supportedBusinessIds = { BusinessId::DEFAULT };

    guard.Cancel();
    deviceStatus.isSynced = true;
    deviceStatus.isSyncInProgress = false;
    NotifySubscribers();
    IAM_LOGI("device synced successfully: %{public}s", deviceKey.GetDesc().c_str());
}

void DeviceStatusManager::SetSubscribeMode(SubscribeMode mode)
{
    if (currentMode_ == mode) {
        return;
    }

    IAM_LOGI("changing subscribe mode: %{public}d -> %{public}d", currentMode_, mode);

    currentMode_ = mode;

    if (mode == SUBSCRIBE_MODE_MANAGE) {
        auto now = GetTimeKeeper().GetSteadyTimeMs();
        ENSURE_OR_RETURN(now.has_value());
        manageSubscribeTime_ = now.value();
        StartPeriodicSync();
    } else {
        manageSubscribeTime_ = std::nullopt;
        StopPeriodicSync();
        RefreshDeviceList(false);
    }
}

std::optional<SteadyTimeMs> DeviceStatusManager::GetManageSubscribeTime() const
{
    return manageSubscribeTime_;
}

std::unique_ptr<Subscription> DeviceStatusManager::SubscribeDeviceStatus(const DeviceKey &deviceKey,
    OnDeviceStatusChange &&callback)
{
    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    DeviceStatusSubscriptionInfo info {};
    info.subscriptionId = subscriptionId;
    info.deviceKey = deviceKey; // specific device
    info.callback = std::move(callback);
    subscriptions_.push_back(info);

    IAM_LOGD("device status subscription added: id=0x%{public}016" PRIX64 " for device %{public}s", subscriptionId,
        deviceKey.GetDesc().c_str());
    RefreshDeviceList(false);

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeDeviceStatus(subscriptionId);
    });
}

bool DeviceStatusManager::UnsubscribeDeviceStatus(SubscribeId subscriptionId)
{
    auto it = std::find_if(subscriptions_.begin(), subscriptions_.end(),
        [subscriptionId](const DeviceStatusSubscriptionInfo &info) { return info.subscriptionId == subscriptionId; });
    if (it != subscriptions_.end()) {
        bool wasSpecificDevice = it->deviceKey.has_value();
        subscriptions_.erase(it);
        IAM_LOGD("device status subscription removed: id=0x%{public}016" PRIX64 "", subscriptionId);
        if (wasSpecificDevice) {
            RefreshDeviceList(false);
        }
        return true;
    }
    IAM_LOGW("device status subscription not found: id=0x%{public}016" PRIX64 "", subscriptionId);
    return false;
}

void DeviceStatusManager::TriggerDeviceSync(const PhysicalDeviceKey &physicalKey)
{
    auto it = deviceStatusMap_.find(physicalKey);
    if (it == deviceStatusMap_.end()) {
        return;
    }

    if (it->second.isSyncInProgress) {
        IAM_LOGI("device already syncing");
        return;
    }

    DeviceStatusEntry &entry = it->second;
    DeviceKey companionDeviceKey = entry.BuildDeviceKey(activeUserId_);

    entry.isSyncInProgress = true;
    ScopeGuard guard([&entry, &companionDeviceKey]() {
        entry.isSyncInProgress = false;
        entry.isSynced = false;
        IAM_LOGE("device %{public}s sync failed", companionDeviceKey.GetDesc().c_str());
    });

    SyncDeviceStatusCallback callback = [weakSelf = weak_from_this(), companionDeviceKey](ResultCode result,
                                            const SyncDeviceStatus &syncDeviceStatus) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->HandleSyncResult(companionDeviceKey, result, syncDeviceStatus);
    };

    auto request = GetRequestFactory().CreateHostSyncDeviceStatusRequest(activeUserId_, companionDeviceKey,
        entry.deviceName, std::move(callback));
    ENSURE_OR_RETURN(request != nullptr);

    bool startRequestRet = GetRequestManager().Start(request);
    ENSURE_OR_RETURN(startRequestRet);

    guard.Cancel();
    IAM_LOGI("SyncDeviceStatus request started for device: %{public}s", companionDeviceKey.GetDesc().c_str());
}

void DeviceStatusManager::StartPeriodicSync()
{
    StopPeriodicSync();
    periodicSyncTimerSubscription_ = RelativeTimer::GetInstance().RegisterPeriodic(
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->RefreshDeviceList(true);
        },
        PERIODIC_SYNC_INTERVAL_MS);
    ENSURE_OR_RETURN(periodicSyncTimerSubscription_ != nullptr);
    IAM_LOGI("periodic sync started");
    RefreshDeviceList(true);
}

void DeviceStatusManager::StopPeriodicSync()
{
    if (periodicSyncTimerSubscription_ != nullptr) {
        periodicSyncTimerSubscription_.reset();
    }
    IAM_LOGI("periodic sync stopped");
}

std::optional<ProtocolId> DeviceStatusManager::NegotiateProtocol(const std::vector<ProtocolId> &remoteProtocols)
{
    ENSURE_OR_RETURN_VAL(localDeviceStatusMgr_ != nullptr, std::nullopt);

    auto localProfile = localDeviceStatusMgr_->GetLocalDeviceProfile();
    const auto &localProtocols = localProfile.protocols;

    for (const auto &localProtocol : localProfile.protocolPriorityList) {
        if (std::find(remoteProtocols.begin(), remoteProtocols.end(), localProtocol) != remoteProtocols.end() &&
            std::find(localProtocols.begin(), localProtocols.end(), localProtocol) != localProtocols.end()) {
            IAM_LOGI("negotiated protocol: %{public}hu", localProtocol);
            return localProtocol;
        }
    }

    IAM_LOGW("no common protocol found");
    return std::nullopt;
}

std::vector<Capability> DeviceStatusManager::NegotiateCapabilities(const std::vector<Capability> &remoteCapabilities)
{
    auto localProfile = localDeviceStatusMgr_->GetLocalDeviceProfile();

    std::vector<Capability> intersection;
    for (const auto &remoteCap : remoteCapabilities) {
        auto it = std::find_if(localProfile.capabilities.begin(), localProfile.capabilities.end(),
            [&remoteCap](const Capability &localCap) { return localCap == remoteCap; });
        if (it != localProfile.capabilities.end()) {
            intersection.push_back(remoteCap);
        }
    }
    return intersection;
}

void DeviceStatusManager::NotifySubscribers()
{
    auto statusList = GetAllDeviceStatus();

    std::vector<OnDeviceStatusChange> callbacks;
    callbacks.reserve(subscriptions_.size());
    for (const auto &sub : subscriptions_) {
        if (sub.callback) {
            callbacks.push_back(sub.callback);
        }
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [callbacks = std::move(callbacks), status = std::move(statusList)]() mutable {
            for (auto &cb : callbacks) {
                if (cb) {
                    cb(status);
                }
            }
        });
}

bool DeviceStatusManager::ShouldMonitorDevice(const PhysicalDeviceKey &physicalKey)
{
    if (currentMode_ == SUBSCRIBE_MODE_MANAGE) {
        return true;
    }

    for (const auto &sub : subscriptions_) {
        if (!sub.deviceKey.has_value()) {
            continue;
        }
        const DeviceKey &subscribedDevice = sub.deviceKey.value();
        if (subscribedDevice.deviceUserId == activeUserId_ && subscribedDevice.idType == physicalKey.idType &&
            subscribedDevice.deviceId == physicalKey.deviceId) {
            return true;
        }
    }

    return false;
}

void DeviceStatusManager::HandleUserIdChange(UserId userId)
{
    if (userId == activeUserId_) {
        IAM_LOGI("active user id is the same, no change");
        return;
    }

    IAM_LOGI("active user id changed from %{public}d to %{public}d", activeUserId_, userId);
    activeUserId_ = userId;
    RefreshDeviceList(false);
}

void DeviceStatusManager::RefreshDeviceList(bool resync)
{
    IAM_LOGI("refreshing device list from all channels, resync=%{public}d", resync);

    auto filteredDevicesMap = CollectFilteredDevices();
    bool deviceChanged = RemoveObsoleteDevices(filteredDevicesMap);
    deviceChanged = AddOrUpdateDevices(filteredDevicesMap, resync) || deviceChanged;
    if (deviceChanged) {
        NotifySubscribers();
    }

    IAM_LOGI("device list refresh completed: filtered=%{public}zu", filteredDevicesMap.size());
}

std::map<PhysicalDeviceKey, PhysicalDeviceStatus> DeviceStatusManager::CollectFilteredDevices()
{
    std::map<PhysicalDeviceKey, PhysicalDeviceStatus> filteredDevicesMap;

    for (const auto &channel : channelMgr_->GetAllChannels()) {
        if (channel == nullptr) {
            IAM_LOGE("channel is null");
            continue;
        }
        ChannelId channelId = channel->GetChannelId();
        if (channelId == ChannelId::INVALID) {
            IAM_LOGE("channel id is invalid");
            continue;
        }
        std::vector<PhysicalDeviceStatus> deviceList = channel->GetAllPhysicalDevices();
        IAM_LOGI("channel %{public}d has %{public}zu devices", channelId, deviceList.size());

        for (const auto &status : deviceList) {
            const PhysicalDeviceKey &physicalKey = status.physicalDeviceKey;

            if (!ShouldMonitorDevice(physicalKey)) {
                continue;
            }

            PhysicalDeviceStatus statusWithChannel = status;
            statusWithChannel.channelId = channelId;

            auto [it, inserted] = filteredDevicesMap.emplace(physicalKey, statusWithChannel);
            if (!inserted) {
                ChannelId existingChannelId = it->second.channelId;
                IAM_LOGE("duplicate device found on multiple channels: device=%{public}s, existingChannel=%{public}d, "
                         "newChannel=%{public}d",
                    GET_MASKED_STR_CSTR(physicalKey.deviceId), existingChannelId, channelId);
            }
        }
    }

    return filteredDevicesMap;
}

bool DeviceStatusManager::RemoveObsoleteDevices(
    const std::map<PhysicalDeviceKey, PhysicalDeviceStatus> &filteredDevicesMap)
{
    bool deviceChanged = false;

    for (auto it = deviceStatusMap_.begin(); it != deviceStatusMap_.end();) {
        if (filteredDevicesMap.find(it->first) == filteredDevicesMap.end()) {
            IAM_LOGI("device removed: %{public}s", GET_MASKED_STR_CSTR(it->first.deviceId));
            it = deviceStatusMap_.erase(it);
            deviceChanged = true;
        } else {
            ++it;
        }
    }

    return deviceChanged;
}

bool DeviceStatusManager::AddOrUpdateDevices(
    const std::map<PhysicalDeviceKey, PhysicalDeviceStatus> &filteredDevicesMap, bool resync)
{
    bool deviceChanged = false;

    for (const auto &pair : filteredDevicesMap) {
        const PhysicalDeviceKey &key = pair.first;
        const PhysicalDeviceStatus &status = pair.second;

        auto it = deviceStatusMap_.find(key);
        if (it == deviceStatusMap_.end()) {
            deviceStatusMap_.emplace(key, status);
            deviceChanged = true;
            IAM_LOGI("device added: %{public}s, channel=%{public}d", GET_MASKED_STR_CSTR(key.deviceId),
                status.channelId);
            TriggerDeviceSync(key);
        } else {
            DeviceStatusEntry &deviceStatus = it->second;
            bool hasChange = deviceStatus.channelId != status.channelId ||
                deviceStatus.deviceName != status.deviceName ||
                deviceStatus.deviceModelInfo != status.deviceModelInfo ||
                deviceStatus.isAuthMaintainActive != status.isAuthMaintainActive;
            if (hasChange) {
                deviceStatus.channelId = status.channelId;
                deviceStatus.deviceName = status.deviceName;
                deviceStatus.deviceModelInfo = status.deviceModelInfo;
                deviceStatus.isAuthMaintainActive = status.isAuthMaintainActive;
                deviceChanged = true;
            }
            if (resync) {
                TriggerDeviceSync(key);
            }
        }
    }

    return deviceChanged;
}

void DeviceStatusManager::HandleChannelDeviceStatusChange(ChannelId channelId,
    const std::vector<PhysicalDeviceStatus> &statusList)
{
    IAM_LOGI("channel device status change: channel=%{public}d, statusList size=%{public}zu", channelId,
        statusList.size());
    RefreshDeviceList(false);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
