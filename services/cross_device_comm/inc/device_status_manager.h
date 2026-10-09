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

#ifndef COMPANION_DEVICE_AUTH_DEVICE_STATUS_MANAGER_H
#define COMPANION_DEVICE_AUTH_DEVICE_STATUS_MANAGER_H

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "channel_manager.h"
#include "connection_manager.h"
#include "cross_device_common.h"
#include "device_status_entry.h"
#include "error_guard.h"
#include "host_sync_device_status_request.h"
#include "local_device_status_manager.h"
#include "misc_manager.h"
#include "request_factory.h"
#include "request_manager.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

enum class DeviceReconcilePolicy : int32_t {
    CHANGED_ONLY = 0,
    REEVALUATE_ALL = 1,
};

// Remote device status management and subscription mode control
class DeviceStatusManager : public std::enable_shared_from_this<DeviceStatusManager>, public NoCopyable {
public:
    static std::shared_ptr<DeviceStatusManager> Create(const std::vector<BusinessId> &hostSupportBusinessIds,
        std::shared_ptr<ConnectionManager> connectionMgr, std::shared_ptr<ChannelManager> channelMgr,
        std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr);

    ~DeviceStatusManager();

    std::optional<DeviceStatus> GetDeviceStatus(const DeviceKey &deviceKey);
    std::optional<ChannelId> GetChannelIdByDeviceKey(const DeviceKey &deviceKey);
    std::vector<DeviceStatus> GetAllDeviceStatus(DeviceStatusFilter filter = DeviceStatusFilter::SYNCED_ONLY);
    std::optional<SteadyTimeMs> GetTemplateStatusSubscribeTimeMs() const;
    void SetTemplateStatusSubscribed(bool isActive);

    std::unique_ptr<Subscription> SubscribeDeviceStatus(OnDeviceStatusChange &&callback);
    std::unique_ptr<Subscription> SubscribeDeviceStatus(const DeviceKey &deviceKey, SyncDemand demand,
        OnDeviceStatusChange &&callback);

    void SetSubscribeMode(SubscribeMode mode);
    SubscribeMode GetSubscribeMode() const;
    ConnectionMode GetCurrentConnectionMode() const;
    void RefreshDeviceStatus();
    bool IsPhysicalOnline(const PhysicalDeviceKey &physicalKey);
    void EnsureDeviceSynced(const PhysicalDeviceKey &physicalKey, OnDeviceSyncResult &&onResult);
    void ResyncDevice(const PhysicalDeviceKey &physicalKey);

private:
    struct DeviceStatusSubscriptionInfo {
        SubscribeId subscriptionId;
        std::optional<DeviceKey> deviceKey;
        OnDeviceStatusChange callback;
        SyncDemand demand { SyncDemand::NONE };
    };

    DeviceStatusManager(const std::vector<BusinessId> &hostSupportBusinessIds,
        std::shared_ptr<ConnectionManager> connectionMgr, std::shared_ptr<ChannelManager> channelMgr,
        std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr);

    bool Initialize();

    void HandleSyncResult(const DeviceKey &deviceKey, uint64_t requestId, ResultCode resultCode,
        const SyncDeviceStatus &syncDeviceStatus);
    void ApplySyncResult(DeviceStatusEntry &deviceStatus, const SyncDeviceStatus &syncDeviceStatus);

    void AttachOrStartDeviceSync(const PhysicalDeviceKey &physicalKey, SyncTriggerReason reason,
        OnDeviceSyncResult onResult = nullptr);
    void HandleSyncFailure(DeviceStatusEntry &deviceStatus, const DeviceKey &deviceKey, ResultCode resultCode,
        ErrorGuard &errorGuard);
    bool NegotiateSyncProtocol(DeviceStatusEntry &deviceStatus, const DeviceKey &deviceKey,
        const SyncDeviceStatus &syncDeviceStatus, ErrorGuard &errorGuard);
    void StartDeviceSync(DeviceStatusEntry &entry, ConnectionMode mode, SyncTriggerReason reason,
        OnDeviceSyncResult &onResult, ErrorGuard &settleGuard);
    void SyncDeviceIfNeeded(DeviceStatusEntry &entry);
    void EscalateSyncToForeground(DeviceStatusEntry &deviceStatus);

    bool UnsubscribeDeviceStatus(SubscribeId subscriptionId);

    std::optional<ProtocolId> NegotiateProtocol(const std::vector<ProtocolId> &remoteProtocols);

    bool ShouldMonitorDevice(const PhysicalDeviceKey &physicalKey);
    SyncDemandLevel ResolveSyncDemandLevel(const PhysicalDeviceKey &physicalKey);

    void HandleChannelDeviceStatusChange(ChannelId channelId, const std::vector<PhysicalDeviceStatus> &statusList);

    void ReconcileDevices(DeviceReconcilePolicy policy);

    std::map<PhysicalDeviceKey, PhysicalDeviceStatus> CollectFilteredDevices();
    bool RemoveObsoleteDevices(const std::map<PhysicalDeviceKey, PhysicalDeviceStatus> &filteredDevicesMap);
    bool AddOrUpdateDevices(const std::map<PhysicalDeviceKey, PhysicalDeviceStatus> &filteredDevicesMap,
        DeviceReconcilePolicy policy);
    bool UpdateExistingDevice(const PhysicalDeviceKey &key, DeviceStatusEntry &deviceStatus,
        const PhysicalDeviceStatus &status, DeviceReconcilePolicy policy);
    void NotifySubscribers();

    std::map<PhysicalDeviceKey, DeviceStatusEntry> deviceStatusMap_;
    SubscribeMode currentMode_ { SUBSCRIBE_MODE_SUBSCRIBED_ONLY };
    std::optional<SteadyTimeMs> templateStatusSubscribeTimeMs_;
    std::vector<DeviceStatusSubscriptionInfo> subscriptions_;
    std::vector<BusinessId> hostSupportBusinessIds_;

    std::map<ChannelId, std::unique_ptr<Subscription>> channelSubscriptions_;

    std::shared_ptr<ConnectionManager> connectionMgr_;
    std::shared_ptr<ChannelManager> channelMgr_;
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_DEVICE_STATUS_MANAGER_H
