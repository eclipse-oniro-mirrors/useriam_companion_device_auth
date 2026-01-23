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
#include "host_sync_device_status_request.h"
#include "local_device_status_manager.h"
#include "misc_manager.h"
#include "request_factory.h"
#include "request_manager.h"
#include "service_common.h"
#include "subscription.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Remote device status management and subscription mode control
class DeviceStatusManager : public NoCopyable, public std::enable_shared_from_this<DeviceStatusManager> {
public:
    static std::shared_ptr<DeviceStatusManager> Create(std::shared_ptr<ConnectionManager> connectionMgr,
        std::shared_ptr<ChannelManager> channelMgr, std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr);

    ~DeviceStatusManager();

    std::optional<DeviceStatus> GetDeviceStatus(const DeviceKey &deviceKey);
    std::optional<ChannelId> GetChannelIdByDeviceKey(const DeviceKey &deviceKey);
    std::vector<DeviceStatus> GetAllDeviceStatus();
    SubscribeMode GetCurrentMode() const
    {
        return currentMode_;
    }
    std::optional<SteadyTimeMs> GetManageSubscribeTime() const;

    std::unique_ptr<Subscription> SubscribeDeviceStatus(OnDeviceStatusChange &&callback);
    std::unique_ptr<Subscription> SubscribeDeviceStatus(const DeviceKey &deviceKey, OnDeviceStatusChange &&callback);

    void SetSubscribeMode(SubscribeMode mode);

private:
    static constexpr int32_t PERIODIC_SYNC_INTERVAL_MS = 60 * 1000; // 60 seconds

    struct DeviceStatusSubscriptionInfo {
        SubscribeId subscriptionId;
        std::optional<DeviceKey> deviceKey;
        OnDeviceStatusChange callback;
    };

    DeviceStatusManager(std::shared_ptr<ConnectionManager> connectionMgr, std::shared_ptr<ChannelManager> channelMgr,
        std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr);

    bool Initialize();

    void HandleSyncResult(const DeviceKey &deviceKey, int32_t resultCode, const SyncDeviceStatus &syncDeviceStatus);

    void TriggerDeviceSync(const PhysicalDeviceKey &physicalKey);

    void StartPeriodicSync();
    void StopPeriodicSync();

    bool UnsubscribeDeviceStatus(SubscribeId subscriptionId);

    std::optional<ProtocolId> NegotiateProtocol(const std::vector<ProtocolId> &remoteProtocols);
    std::vector<Capability> NegotiateCapabilities(const std::vector<Capability> &remoteCapabilities);

    DeviceKey MakeTemporaryDeviceKey(const PhysicalDeviceKey &physicalKey);

    bool ShouldMonitorDevice(const PhysicalDeviceKey &physicalKey);

    void HandleUserIdChange(UserId userId);
    void HandleChannelDeviceStatusChange(ChannelId channelId, const std::vector<PhysicalDeviceStatus> &statusList);

    void RefreshDeviceList(bool resync);

    std::map<PhysicalDeviceKey, PhysicalDeviceStatus> CollectFilteredDevices();
    bool RemoveObsoleteDevices(const std::map<PhysicalDeviceKey, PhysicalDeviceStatus> &filteredDevicesMap);
    bool AddOrUpdateDevices(const std::map<PhysicalDeviceKey, PhysicalDeviceStatus> &filteredDevicesMap, bool resync);
    void NotifySubscribers();

    int32_t activeUserId_ { INVALID_USER_ID };
    std::map<PhysicalDeviceKey, DeviceStatusEntry> deviceStatusMap_;
    SubscribeMode currentMode_ { SUBSCRIBE_MODE_AUTH };
    std::optional<SteadyTimeMs> manageSubscribeTime_;
    std::vector<DeviceStatusSubscriptionInfo> subscriptions_;
    std::unique_ptr<Subscription> periodicSyncTimerSubscription_;

    std::unique_ptr<Subscription> activeUserIdSubscription_;
    std::map<ChannelId, std::unique_ptr<Subscription>> channelSubscriptions_;

    std::shared_ptr<ConnectionManager> connectionMgr_;
    std::shared_ptr<ChannelManager> channelMgr_;
    std::shared_ptr<LocalDeviceStatusManager> localDeviceStatusMgr_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_DEVICE_STATUS_MANAGER_H
