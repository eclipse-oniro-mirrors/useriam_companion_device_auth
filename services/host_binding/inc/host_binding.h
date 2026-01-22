/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMPANION_DEVICE_AUTH_HOST_BINDING_H
#define COMPANION_DEVICE_AUTH_HOST_BINDING_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "cross_device_comm_manager.h"
#include "host_binding_manager.h"
#include "relative_timer.h"
#include "security_agent.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class HostBinding : public NoCopyable, public std::enable_shared_from_this<HostBinding> {
public:
    static std::shared_ptr<HostBinding> Create(const PersistedHostBindingStatus &persistedStatus);

    ~HostBinding() override;

    uint32_t GetBindingId() const
    {
        return status_.bindingId;
    }
    int32_t GetCompanionUserId() const
    {
        return status_.companionUserId;
    }
    const DeviceKey &GetHostDeviceKey() const
    {
        return status_.hostDeviceStatus.deviceKey;
    }
    const HostBindingStatus &GetStatus() const
    {
        return status_;
    }
    const char *GetDescription() const
    {
        return description_.c_str();
    }
    void SetTokenValid(bool isTokenValid);

private:
    explicit HostBinding(const PersistedHostBindingStatus &persistedStatus);
    bool Initialize();
    void HandleDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList);
    void HandleHostDeviceStatusUpdate(const DeviceStatus &deviceStatus);
    void HandleHostDeviceOffline();
    void HandleAuthMaintainActiveChanged(bool isActive);

    HostBindingStatus status_;
    std::unique_ptr<Subscription> deviceStatusSubscription_;
    std::unique_ptr<Subscription> localDeviceStatusSubscription_;

    std::string description_ = "";
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_BINDING_H
