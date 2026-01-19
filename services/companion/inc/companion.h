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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_H
#define COMPANION_DEVICE_AUTH_COMPANION_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "nocopyable.h"

#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionManagerImpl;

class Companion : public NoCopyable, public std::enable_shared_from_this<Companion> {
public:
    static std::shared_ptr<Companion> Create(const PersistedCompanionStatus &persistedStatus,
        const std::weak_ptr<CompanionManagerImpl> &managerWeakPtr);

    ~Companion() override;

    uint64_t GetTemplateId() const
    {
        return status_.templateId;
    }
    int32_t GetHostUserId() const
    {
        return status_.hostUserId;
    }
    const DeviceKey &GetCompanionDeviceKey() const
    {
        return status_.companionDeviceStatus.deviceKey;
    }
    CompanionStatus GetStatus() const
    {
        return status_;
    }
    std::string GetDescription() const
    {
        return description_;
    }

    void SetEnabledBusinessIds(const std::vector<BusinessId> &enabledBusinessIds);
    void SetCompanionValid(bool isValid);
    void SetCompanionTokenAtl(std::optional<Atl> tokenAtl);
    void SetDeviceNames(const std::string &deviceName, const std::string &deviceUserName);
    void RefreshTokenTimer();
    void NotifySubscribers();

private:
    explicit Companion(const PersistedCompanionStatus &persistedStatus,
        const std::weak_ptr<CompanionManagerImpl> &managerWeakPtr);
    bool Initialize();
    void HandleDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList);
    void HandleDeviceStatusUpdate(const DeviceStatus &deviceStatus);
    void HandleDeviceOffline();

    CompanionStatus status_;
    std::unique_ptr<Subscription> deviceStatusSubscription_;
    std::unique_ptr<Subscription> tokenTimeoutSubscription_;
    std::string description_;
    std::weak_ptr<CompanionManagerImpl> managerWeakPtr_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_H
