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
#include "cda_scope_guard.h"
#include "channel_manager.h"
#include "companion_manager.h"
#include "connection_manager.h"
#include "error_guard.h"
#include "host_sync_device_status_request.h"
#include "service_common.h"
#include "service_converter.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "time_keeper.h"
#include "user_key_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_DEVICE_STATUS_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
bool ShouldInvalidateCachedSync(ResultCode resultCode)
{
    return resultCode == PROTOCOL_NEGOTIATION_FAILED || resultCode == PEER_SYNC_FAILED;
}

bool ShouldStopRetry(ResultCode resultCode)
{
    return resultCode == PROTOCOL_NEGOTIATION_FAILED || resultCode == PEER_SYNC_FAILED ||
        resultCode == PEER_SERVICE_NOT_AVAILABLE || resultCode == COORDINATOR_REJECTED;
}
} // namespace

std::shared_ptr<DeviceStatusManager> DeviceStatusManager::Create(const std::vector<BusinessId> &hostSupportBusinessIds,
    std::shared_ptr<ConnectionManager> connectionMgr, std::shared_ptr<ChannelManager> channelMgr,
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr)
{
    // clang-format off
    auto manager = std::shared_ptr<DeviceStatusManager>(new (std::nothrow)
        DeviceStatusManager(hostSupportBusinessIds, connectionMgr, channelMgr, localDeviceStatusMgr));
    // clang-format on
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);

    if (!manager->Initialize()) {
        IAM_LOGE("failed to initialize DeviceStatusManager");
        return nullptr;
    }

    return manager;
}

DeviceStatusManager::DeviceStatusManager(const std::vector<BusinessId> &hostSupportBusinessIds,
    std::shared_ptr<ConnectionManager> connectionMgr, std::shared_ptr<ChannelManager> channelMgr,
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr)
    : hostSupportBusinessIds_(hostSupportBusinessIds),
      connectionMgr_(connectionMgr),
      channelMgr_(channelMgr),
      localDeviceStatusMgr_(localDeviceStatusMgr)
{
}

DeviceStatusManager::~DeviceStatusManager()
{
}

bool DeviceStatusManager::Initialize()
{
    ENSURE_OR_RETURN_VAL(connectionMgr_ != nullptr, false);
    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, false);
    ENSURE_OR_RETURN_VAL(localDeviceStatusMgr_ != nullptr, false);

    for (const auto &channel : channelMgr_->GetAllChannels()) {
        ENSURE_OR_CONTINUE(channel != nullptr);
        ChannelId channelId = channel->GetChannelId();
        auto subscription = channel->SubscribePhysicalDeviceStatus(
            [weakSelf = weak_from_this(), channelId](const std::vector<PhysicalDeviceStatus> &statusList) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleChannelDeviceStatusChange(channelId, statusList);
            });
        ENSURE_OR_RETURN_VAL(subscription != nullptr, false);
        channelSubscriptions_[channelId] = std::move(subscription);
    }

    return true;
}

std::optional<DeviceStatus> DeviceStatusManager::GetDeviceStatus(const DeviceKey &deviceKey)
{
    PhysicalDeviceKey physicalKey {};
    physicalKey.idType = deviceKey.idType;
    physicalKey.deviceId = deviceKey.deviceId;

    auto it = deviceStatusMap_.find(physicalKey);
    if (it != deviceStatusMap_.end() && it->second.isSynced) {
        return it->second.BuildDeviceStatus();
    }

    return std::nullopt;
}

std::optional<ChannelId> DeviceStatusManager::GetChannelIdByDeviceKey(const DeviceKey &deviceKey)
{
    PhysicalDeviceKey physicalKey {};
    physicalKey.idType = deviceKey.idType;
    physicalKey.deviceId = deviceKey.deviceId;

    auto it = deviceStatusMap_.find(physicalKey);
    ENSURE_OR_RETURN_VAL(it != deviceStatusMap_.end(), std::nullopt);
    ENSURE_OR_RETURN_VAL(it->second.channelId != ChannelId::INVALID, std::nullopt);
    return it->second.channelId;
}

std::vector<DeviceStatus> DeviceStatusManager::GetAllDeviceStatus(DeviceStatusFilter filter)
{
    std::vector<DeviceStatus> result;

    for (const auto &pair : deviceStatusMap_) {
        if (pair.second.isSynced || (filter == DeviceStatusFilter::INCLUDE_UNSYNCED && pair.second.reportUnsynced)) {
            result.push_back(pair.second.BuildDeviceStatus());
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
    subscriptions_.push_back(std::move(info));

    IAM_LOGD("device status subscription added: id=0x%{public}016" PRIX64 " (all devices)", subscriptionId);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeDeviceStatus(subscriptionId);
    });
}

void DeviceStatusManager::HandleSyncResult(const DeviceKey &deviceKey, uint64_t attemptId, ResultCode resultCode,
    const SyncDeviceStatus &syncDeviceStatus)
{
    IAM_LOGI("device sync result: device=%{public}s, result=%{public}d", deviceKey.GetDesc().c_str(), resultCode);

    PhysicalDeviceKey physicalKey {};
    physicalKey.idType = deviceKey.idType;
    physicalKey.deviceId = deviceKey.deviceId;

    auto it = deviceStatusMap_.find(physicalKey);
    if (it == deviceStatusMap_.end()) {
        IAM_LOGE("device not found in cache");
        return;
    }

    if (it->second.inProgressAttemptId != attemptId) {
        IAM_LOGI("drop stale sync completion for device %{public}s", deviceKey.GetDesc().c_str());
        return;
    }

    DeviceStatusEntry &deviceStatus = it->second;

    ErrorGuard errorGuard([&deviceStatus, this](ResultCode result) {
        if (result == ResultCode::SUCCESS) {
            deviceStatus.isSynced = true;
        } else if (ShouldInvalidateCachedSync(result)) {
            deviceStatus.isSynced = false;
        }
        deviceStatus.isSyncInProgress = false;
        NotifySubscribers();
        deviceStatus.NotifySyncWaiters(result);
        if (deviceStatus.pendingResync) {
            IAM_LOGI("pending resync marker, start make-up round: %{public}s",
                GET_MASKED_STR_CSTR(deviceStatus.physicalDeviceKey.deviceId));
            AttachOrStartDeviceSync(deviceStatus.physicalDeviceKey, SyncTriggerReason::RESYNC);
        }
    });
    errorGuard.UpdateErrorCode(resultCode);

    if (resultCode != SUCCESS) {
        HandleSyncFailure(deviceStatus, deviceKey, resultCode, errorGuard);
        return;
    }

    if (!NegotiateSyncProtocol(deviceStatus, deviceKey, syncDeviceStatus, errorGuard)) {
        return;
    }

    ApplySyncResult(deviceStatus, syncDeviceStatus);
    deviceStatus.OnSyncSuccess();

    auto newDeviceKey = deviceStatus.BuildDeviceKey();
    IAM_LOGI("device synced successfully: %{public}s", newDeviceKey.GetDesc().c_str());
}

void DeviceStatusManager::HandleSyncFailure(DeviceStatusEntry &deviceStatus, const DeviceKey &deviceKey,
    ResultCode resultCode, ErrorGuard &errorGuard)
{
    if (!ShouldStopRetry(resultCode)) {
        IAM_LOGE("sync failed: %{public}d", resultCode);
        deviceStatus.OnSyncFailure();
        return;
    }

    IAM_LOGW("terminal sync failure %{public}d, abort retry and clear backoff state: device=%{public}s", resultCode,
        deviceKey.GetDesc().c_str());
    deviceStatus.OnSyncAbort();
    if (resultCode == COORDINATOR_REJECTED && deviceStatus.inProgressConnectionMode == ConnectionMode::BACKGROUND &&
        ResolveSyncDemandLevel(deviceStatus.physicalDeviceKey) == SyncDemandLevel::FOREGROUND) {
        errorGuard.Cancel();
        EscalateSyncToForeground(deviceStatus);
    }
}

bool DeviceStatusManager::NegotiateSyncProtocol(DeviceStatusEntry &deviceStatus, const DeviceKey &deviceKey,
    const SyncDeviceStatus &syncDeviceStatus, ErrorGuard &errorGuard)
{
    if (!syncDeviceStatus.needSync) {
        return true;
    }
    auto negotiatedProtocol = NegotiateProtocol(syncDeviceStatus.protocolIdList);
    if (!negotiatedProtocol.has_value()) {
        IAM_LOGE("protocol negotiation failed: %{public}s", deviceKey.GetDesc().c_str());
        errorGuard.UpdateErrorCode(ResultCode::PROTOCOL_NEGOTIATION_FAILED);
        deviceStatus.OnSyncAbort();
        return false;
    }
    deviceStatus.protocolId = negotiatedProtocol.value();
    return true;
}

void DeviceStatusManager::ApplySyncResult(DeviceStatusEntry &deviceStatus, const SyncDeviceStatus &syncDeviceStatus)
{
    deviceStatus.deviceUserName = syncDeviceStatus.deviceUserName;
    deviceStatus.syncDeviceName = syncDeviceStatus.deviceName;
    deviceStatus.deviceUserKey = syncDeviceStatus.deviceUserKey;
    deviceStatus.deviceSubProfileName = syncDeviceStatus.deviceSubProfileName;
    deviceStatus.secureProtocolId = syncDeviceStatus.secureProtocolId;
    deviceStatus.capabilities = syncDeviceStatus.capabilityList;
    deviceStatus.SetSyncCompanionBusinessIds(syncDeviceStatus.businessIdList);
}

void DeviceStatusManager::SetSubscribeMode(SubscribeMode mode)
{
    if (currentMode_ == mode) {
        return;
    }

    IAM_LOGI("changing subscribe mode: %{public}d -> %{public}d", currentMode_, mode);
    bool changeToSubscribeAll = mode == SUBSCRIBE_MODE_ALL_DEVICES;
    currentMode_ = mode;
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), changeToSubscribeAll]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        if (changeToSubscribeAll) {
            self->RefreshDeviceStatus();
        } else {
            self->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
        }
    });
}

void DeviceStatusManager::SetTemplateStatusSubscribed(bool isActive)
{
    if (isActive) {
        if (templateStatusSubscribeTimeMs_.has_value()) {
            return;
        }
        auto now = GetTimeKeeper().GetSteadyTimeMs();
        ENSURE_OR_RETURN(now.has_value());
        templateStatusSubscribeTimeMs_ = now.value();
        TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            for (auto &pair : self->deviceStatusMap_) {
                self->SyncDeviceIfNeeded(pair.second);
            }
        });
        return;
    }
    templateStatusSubscribeTimeMs_ = std::nullopt;
}

SubscribeMode DeviceStatusManager::GetSubscribeMode() const
{
    return currentMode_;
}

ConnectionMode DeviceStatusManager::GetCurrentConnectionMode() const
{
    return currentMode_ == SUBSCRIBE_MODE_ALL_DEVICES ? ConnectionMode::FOREGROUND : ConnectionMode::BACKGROUND;
}

void DeviceStatusManager::RefreshDeviceStatus()
{
    IAM_LOGI("refresh physical device status");
    for (const auto &channel : channelMgr_->GetAllChannels()) {
        if (channel != nullptr) {
            channel->RefreshPhysicalDeviceStatus();
        }
    }
    ReconcileDevices(DeviceReconcilePolicy::REEVALUATE_ALL);
}

std::optional<SteadyTimeMs> DeviceStatusManager::GetTemplateStatusSubscribeTimeMs() const
{
    return templateStatusSubscribeTimeMs_;
}

std::unique_ptr<Subscription> DeviceStatusManager::SubscribeDeviceStatus(const DeviceKey &deviceKey, SyncDemand demand,
    OnDeviceStatusChange &&callback)
{
    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    DeviceStatusSubscriptionInfo info {};
    info.subscriptionId = subscriptionId;
    info.deviceKey = deviceKey; // specific device
    info.callback = std::move(callback);
    info.demand = demand;
    PhysicalDeviceKey physicalKey = FromDeviceKey(deviceKey);
    auto demandBefore = ResolveSyncDemandLevel(physicalKey);
    subscriptions_.push_back(std::move(info));
    auto demandAfter = ResolveSyncDemandLevel(physicalKey);
    ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);

    if (demandAfter > demandBefore) {
        auto it = deviceStatusMap_.find(physicalKey);
        if (it != deviceStatusMap_.end() && !it->second.isSynced && !it->second.isSyncInProgress) {
            AttachOrStartDeviceSync(physicalKey, SyncTriggerReason::EXTERNAL_REFRESH);
        }
    }

    IAM_LOGI(
        "device status subscription added: device=%{public}s, demand=%{public}d, subscriptionId=0x%{public}016" PRIX64
        "",
        GET_MASKED_STR_CSTR(deviceKey.deviceId), demand, subscriptionId);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscriptionId]() {
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
        subscriptions_.erase(it);
        IAM_LOGD("device status subscription removed: id=0x%{public}016" PRIX64 "", subscriptionId);
        TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
        });
        return true;
    }
    IAM_LOGE("device status subscription not found: id=0x%{public}016" PRIX64 "", subscriptionId);
    return false;
}

bool DeviceStatusManager::IsPhysicalOnline(const PhysicalDeviceKey &physicalKey)
{
    return deviceStatusMap_.find(physicalKey) != deviceStatusMap_.end();
}

void DeviceStatusManager::EnsureDeviceSynced(const PhysicalDeviceKey &physicalKey, OnDeviceSyncResult &&onResult)
{
    ErrorGuard settleGuard([&onResult](ResultCode result) {
        TaskRunnerManager::GetInstance().PostTaskOnResident([result, cb = std::move(onResult)]() {
            if (cb) {
                cb(result);
            }
        });
    });

    auto it = deviceStatusMap_.find(physicalKey);
    if (it == deviceStatusMap_.end()) {
        IAM_LOGI("ensure sync rejected, device not adopted: %{public}s", GET_MASKED_STR_CSTR(physicalKey.deviceId));
        settleGuard.UpdateErrorCode(ResultCode::COMMUNICATION_ERROR);
        return;
    }
    if (ResolveSyncDemandLevel(physicalKey) == SyncDemandLevel::NONE) {
        IAM_LOGI("ensure sync rejected, device has no sync demand: %{public}s",
            GET_MASKED_STR_CSTR(physicalKey.deviceId));
        settleGuard.UpdateErrorCode(ResultCode::GENERAL_ERROR);
        return;
    }
    if (it->second.isSynced) {
        IAM_LOGI("device already synced, ensure short-circuits: %{public}s", GET_MASKED_STR_CSTR(physicalKey.deviceId));
        settleGuard.UpdateErrorCode(ResultCode::SUCCESS);
        return;
    }
    settleGuard.Cancel();
    AttachOrStartDeviceSync(physicalKey, SyncTriggerReason::BRING_ONLINE, std::move(onResult));
}

void DeviceStatusManager::ResyncDevice(const PhysicalDeviceKey &physicalKey)
{
    auto it = deviceStatusMap_.find(physicalKey);
    if (it == deviceStatusMap_.end()) {
        IAM_LOGW("resync ignored, device not adopted: %{public}s", GET_MASKED_STR_CSTR(physicalKey.deviceId));
        return;
    }
    if (ResolveSyncDemandLevel(physicalKey) == SyncDemandLevel::NONE) {
        IAM_LOGW("resync ignored, device has no sync demand: %{public}s", GET_MASKED_STR_CSTR(physicalKey.deviceId));
        return;
    }
    AttachOrStartDeviceSync(physicalKey, SyncTriggerReason::RESYNC);
}

void DeviceStatusManager::AttachOrStartDeviceSync(const PhysicalDeviceKey &physicalKey, SyncTriggerReason reason,
    OnDeviceSyncResult onResult)
{
    auto it = deviceStatusMap_.find(physicalKey);
    if (it == deviceStatusMap_.end()) {
        IAM_LOGI("device not adopted, skip internal sync trigger: %{public}s",
            GET_MASKED_STR_CSTR(physicalKey.deviceId));
        return;
    }
    DeviceStatusEntry &entry = it->second;
    ErrorGuard settleGuard([&onResult](ResultCode result) {
        TaskRunnerManager::GetInstance().PostTaskOnResident([result, onResult = std::move(onResult)]() {
            if (onResult) {
                onResult(result);
            }
        });
    });

    SyncDemandLevel demand = ResolveSyncDemandLevel(physicalKey);
    if (demand == SyncDemandLevel::NONE) {
        IAM_LOGI("device has no sync demand, skip trigger: %{public}s", GET_MASKED_STR_CSTR(physicalKey.deviceId));
        return;
    }
    ConnectionMode mode =
        demand == SyncDemandLevel::FOREGROUND ? ConnectionMode::FOREGROUND : ConnectionMode::BACKGROUND;

    if (entry.isSyncInProgress) {
        IAM_LOGI("device already syncing, attach: %{public}s", GET_MASKED_STR_CSTR(physicalKey.deviceId));
        if (reason == SyncTriggerReason::RESYNC) {
            entry.pendingResync = true;
        }
        if (onResult != nullptr) {
            entry.syncWaiters.push_back(std::move(onResult));
        }
        settleGuard.Cancel();
        return;
    }

    StartDeviceSync(entry, mode, reason, onResult, settleGuard);
}

void DeviceStatusManager::StartDeviceSync(DeviceStatusEntry &entry, ConnectionMode mode, SyncTriggerReason reason,
    OnDeviceSyncResult &onResult, ErrorGuard &settleGuard)
{
    if (reason != SyncTriggerReason::BACKOFF_RETRY && reason != SyncTriggerReason::MODE_ESCALATION) {
        entry.ResetRetry();
    }

    DeviceKey companionDeviceKey = entry.BuildDeviceKey();

    uint64_t attemptId = GetMiscManager().GetNextGlobalId();
    entry.inProgressAttemptId = attemptId;
    entry.inProgressConnectionMode = mode;
    entry.pendingResync = false;
    entry.syncWaiters.clear();
    if (onResult != nullptr) {
        entry.syncWaiters.push_back(std::move(onResult));
    }
    settleGuard.Cancel();

    entry.isSyncInProgress = true;
    ScopeGuard guard([&entry, &companionDeviceKey]() {
        entry.isSyncInProgress = false;
        IAM_LOGE("device %{public}s sync failed to start", companionDeviceKey.GetDesc().c_str());
        entry.OnSyncFailure();
        entry.NotifySyncWaiters(ResultCode::GENERAL_ERROR);
    });

    SyncDeviceStatusCallback callback = [weakSelf = weak_from_this(), companionDeviceKey, attemptId](ResultCode result,
                                            const SyncDeviceStatus &syncDeviceStatus) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->HandleSyncResult(companionDeviceKey, attemptId, result, syncDeviceStatus);
    };

    auto activeUserKey = GetUserKeyManager().GetUnlockedActiveUserkey();
    auto request = GetRequestFactory().CreateHostSyncDeviceStatusRequest(activeUserKey, companionDeviceKey, mode,
        reason, std::move(callback));
    ENSURE_OR_RETURN(request != nullptr);

    bool startRequestRet = GetRequestManager().Start(request);
    ENSURE_OR_RETURN(startRequestRet);

    guard.Cancel();
    IAM_LOGI("SyncDeviceStatus request started for device: %{public}s, reason=%{public}d",
        companionDeviceKey.GetDesc().c_str(), static_cast<int32_t>(reason));
}

void DeviceStatusManager::EscalateSyncToForeground(DeviceStatusEntry &deviceStatus)
{
    IAM_LOGI("escalate device sync to foreground: device=%{public}s",
        GET_MASKED_STR_CSTR(deviceStatus.physicalDeviceKey.deviceId));
    deviceStatus.isSyncInProgress = false;

    AttachOrStartDeviceSync(deviceStatus.physicalDeviceKey, SyncTriggerReason::MODE_ESCALATION,
        deviceStatus.TakeCombinedSyncWaiter());
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

    IAM_LOGE("no common protocol found");
    return std::nullopt;
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
    if (currentMode_ == SUBSCRIBE_MODE_ALL_DEVICES) {
        return true;
    }

    for (const auto &sub : subscriptions_) {
        if (!sub.deviceKey.has_value()) {
            continue;
        }
        const DeviceKey &subscribedDevice = sub.deviceKey.value();
        if (subscribedDevice.idType == physicalKey.idType && subscribedDevice.deviceId == physicalKey.deviceId) {
            return true;
        }
    }

    return false;
}

void DeviceStatusManager::SyncDeviceIfNeeded(DeviceStatusEntry &entry)
{
    if (ResolveSyncDemandLevel(entry.physicalDeviceKey) == SyncDemandLevel::NONE) {
        return;
    }
    if (entry.isSyncInProgress) {
        return;
    }
    if (entry.isSynced) {
        auto windowStart = GetTemplateStatusSubscribeTimeMs();
        if (!windowStart.has_value() || entry.lastSyncTimeMs >= windowStart.value()) {
            return;
        }
    }
    AttachOrStartDeviceSync(entry.physicalDeviceKey, SyncTriggerReason::EXTERNAL_REFRESH);
}

SyncDemandLevel DeviceStatusManager::ResolveSyncDemandLevel(const PhysicalDeviceKey &physicalKey)
{
    if (currentMode_ == SUBSCRIBE_MODE_ALL_DEVICES) {
        IAM_LOGI("sync demand foreground by all-devices mode: device=%{public}s",
            GET_MASKED_STR_CSTR(physicalKey.deviceId));
        return SyncDemandLevel::FOREGROUND;
    }

    SyncDemandLevel resolvedDemand = SyncDemandLevel::NONE;
    for (const auto &sub : subscriptions_) {
        if (!sub.deviceKey.has_value() || sub.demand == SyncDemand::NONE) {
            continue;
        }
        const DeviceKey &subscribedDevice = sub.deviceKey.value();
        if (subscribedDevice.idType != physicalKey.idType || subscribedDevice.deviceId != physicalKey.deviceId) {
            continue;
        }
        if (sub.demand == SyncDemand::FOREGROUND) {
            IAM_LOGI("demand foreground by subscription: device=%{public}s, subscriptionId=0x%{public}016" PRIX64 "",
                GET_MASKED_STR_CSTR(physicalKey.deviceId), sub.subscriptionId);
            return SyncDemandLevel::FOREGROUND;
        }
        resolvedDemand = SyncDemandLevel::BACKGROUND;
    }
    return resolvedDemand;
}

void DeviceStatusManager::ReconcileDevices(DeviceReconcilePolicy policy)
{
    IAM_LOGI("reconciling devices from all channels, policy=%{public}d", static_cast<int32_t>(policy));

    auto filteredDevicesMap = CollectFilteredDevices();
    bool deviceChanged = RemoveObsoleteDevices(filteredDevicesMap);
    deviceChanged = AddOrUpdateDevices(filteredDevicesMap, policy) || deviceChanged;
    if (deviceChanged) {
        NotifySubscribers();
    }

    IAM_LOGI("device reconcile completed: filtered=%{public}zu", filteredDevicesMap.size());
}

std::map<PhysicalDeviceKey, PhysicalDeviceStatus> DeviceStatusManager::CollectFilteredDevices()
{
    std::map<PhysicalDeviceKey, PhysicalDeviceStatus> filteredDevicesMap;
    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, filteredDevicesMap);

    for (const auto &channel : channelMgr_->GetAllChannels()) {
        ENSURE_OR_CONTINUE(channel != nullptr);
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
            it->second.NotifySyncWaiters(ResultCode::GENERAL_ERROR);
            it = deviceStatusMap_.erase(it);
            deviceChanged = true;
        } else {
            ++it;
        }
    }

    return deviceChanged;
}

bool DeviceStatusManager::AddOrUpdateDevices(
    const std::map<PhysicalDeviceKey, PhysicalDeviceStatus> &filteredDevicesMap, DeviceReconcilePolicy policy)
{
    bool deviceChanged = false;

    for (const auto &pair : filteredDevicesMap) {
        const PhysicalDeviceKey &key = pair.first;
        const PhysicalDeviceStatus &status = pair.second;

        auto it = deviceStatusMap_.find(key);
        if (it == deviceStatusMap_.end()) {
            DeviceStatusEntry entry(
                status,
                [weakSelf = weak_from_this(), key]() {
                    auto self = weakSelf.lock();
                    ENSURE_OR_RETURN(self != nullptr);
                    // Retry-fire re-entry: launch only — do NOT reset backoff, or the delay never grows.
                    self->AttachOrStartDeviceSync(key, SyncTriggerReason::BACKOFF_RETRY);
                },
                hostSupportBusinessIds_);
            deviceStatusMap_.emplace(key, std::move(entry));
            deviceChanged = true;
            IAM_LOGI("device added: %{public}s, channel=%{public}d", GET_MASKED_STR_CSTR(key.deviceId),
                status.channelId);
            if (policy == DeviceReconcilePolicy::REEVALUATE_ALL) {
                AttachOrStartDeviceSync(key, SyncTriggerReason::EXTERNAL_REFRESH);
            } else {
                AttachOrStartDeviceSync(key, SyncTriggerReason::DEVICE_ONLINE);
            }
        } else {
            deviceChanged = UpdateExistingDevice(key, it->second, status, policy) || deviceChanged;
        }
    }

    return deviceChanged;
}

bool DeviceStatusManager::UpdateExistingDevice(const PhysicalDeviceKey &key, DeviceStatusEntry &deviceStatus,
    const PhysicalDeviceStatus &status, DeviceReconcilePolicy policy)
{
    bool effectiveBusinessIdsChanged = deviceStatus.SetPhysicalCompanionBusinessIds(status.supportedBusinessIds);
    bool hasChange = deviceStatus.channelId != status.channelId ||
        deviceStatus.physicalDeviceName != status.deviceName ||
        deviceStatus.deviceModelInfo != status.deviceModelInfo || deviceStatus.deviceType != status.deviceType ||
        deviceStatus.atlRevokeDelayMs != status.atlRevokeDelayMs || deviceStatus.refreshToken != status.refreshToken ||
        deviceStatus.reportUnsynced != status.reportUnsynced || effectiveBusinessIdsChanged;
    if (hasChange) {
        deviceStatus.channelId = status.channelId;
        deviceStatus.physicalDeviceName = status.deviceName;
        deviceStatus.deviceModelInfo = status.deviceModelInfo;
        deviceStatus.deviceType = status.deviceType;
        deviceStatus.atlRevokeDelayMs = status.atlRevokeDelayMs;
        deviceStatus.refreshToken = status.refreshToken;
        deviceStatus.reportUnsynced = status.reportUnsynced;
    }
    if (policy == DeviceReconcilePolicy::REEVALUATE_ALL) {
        SyncDeviceIfNeeded(deviceStatus);
    } else if (hasChange) {
        AttachOrStartDeviceSync(key, SyncTriggerReason::DEVICE_INFO_CHANGED);
    }
    return hasChange;
}

void DeviceStatusManager::HandleChannelDeviceStatusChange(ChannelId channelId,
    const std::vector<PhysicalDeviceStatus> &statusList)
{
    IAM_LOGI("channel device status change: channel=%{public}d, statusList size=%{public}zu", channelId,
        statusList.size());
    ReconcileDevices(DeviceReconcilePolicy::CHANGED_ONLY);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
