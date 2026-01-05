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

#ifndef COMPANION_DEVICE_AUTH_LOCAL_DEVICE_STATUS_MANAGER_H
#define COMPANION_DEVICE_AUTH_LOCAL_DEVICE_STATUS_MANAGER_H

#include <atomic>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "nocopyable.h"

#include "channel_manager.h"
#include "cross_device_common.h"
#include "service_common.h"
#include "subscription.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class LocalDeviceStatusManager : public NoCopyable, public std::enable_shared_from_this<LocalDeviceStatusManager> {
public:
    static std::shared_ptr<LocalDeviceStatusManager> Create(std::shared_ptr<ChannelManager> channelMgr);

    ~LocalDeviceStatusManager() = default;

    virtual bool IsAuthMaintainActive();
    virtual std::unique_ptr<Subscription> SubscribeIsAuthMaintainActive(OnAuthMaintainActiveChange &&callback);

    virtual std::map<ChannelId, DeviceKey> GetLocalDeviceKeys();
    virtual std::optional<DeviceKey> GetLocalDeviceKey(ChannelId channelId);
    virtual LocalDeviceProfile GetLocalDeviceProfile();

    virtual void SetAuthMaintainActive(bool isActive);

#ifndef ENABLE_TEST
private:
#endif
    explicit LocalDeviceStatusManager(std::shared_ptr<ChannelManager> channelMgr);
    bool Init();

    std::shared_ptr<ChannelManager> channelMgr_;
    LocalDeviceProfile profile_;
    LocalDeviceAuthState authState_;

    std::map<int32_t, std::function<void(bool)>> statusSubscribers_;
    std::atomic<int32_t> nextSubscriptionId_ { 1 };
    std::unique_ptr<Subscription> authMaintainSubscription_;
    std::unique_ptr<Subscription> activeUserIdSubscription_;

    void NotifyStatusChange();
    void Unsubscribe(int32_t subscriptionId);
    void OnActiveUserIdChanged(UserId userId);
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_LOCAL_DEVICE_STATUS_MANAGER_H
