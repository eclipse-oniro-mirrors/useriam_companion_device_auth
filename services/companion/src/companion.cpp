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

#include "companion.h"

#include <algorithm>
#include <sstream>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "companion_manager_impl.h"
#include "relative_timer.h"
#include "singleton_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<Companion> Companion::Create(const PersistedCompanionStatus &persistedStatus,
    const std::weak_ptr<CompanionManagerImpl> &managerWeakPtr)
{
    auto companion = std::shared_ptr<Companion>(new (std::nothrow) Companion(persistedStatus, managerWeakPtr));
    ENSURE_OR_RETURN_VAL(companion != nullptr, nullptr);

    if (!companion->Initialize()) {
        IAM_LOGE("%{public}s failed to initialize", companion->GetDescription().c_str());
        return nullptr;
    }

    IAM_LOGI("%{public}s created", companion->GetDescription().c_str());
    return companion;
}

Companion::Companion(const PersistedCompanionStatus &persistedStatus,
    const std::weak_ptr<CompanionManagerImpl> &managerWeakPtr)
    : managerWeakPtr_(managerWeakPtr)
{
    status_.FromPersisted(persistedStatus);
    std::ostringstream oss;
    oss << "CP_" << GET_TRUNCATED_STRING(status_.templateId);
    description_ = oss.str();
}

Companion::~Companion()
{
}

bool Companion::Initialize()
{
    deviceStatusSubscription_ =
        GetCrossDeviceCommManager().SubscribeDeviceStatus(status_.companionDeviceStatus.deviceKey,
            [weakSelf = weak_from_this()](const std::vector<DeviceStatus> &deviceStatusList) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->HandleDeviceStatusChanged(deviceStatusList);
            });
    if (deviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe device status", GetDescription().c_str());
        return false;
    }

    auto initialStatus = GetCrossDeviceCommManager().GetDeviceStatus(status_.companionDeviceStatus.deviceKey);
    if (initialStatus.has_value()) {
        HandleDeviceStatusUpdate(initialStatus.value());
    } else {
        HandleDeviceOffline();
    }

    return true;
}

void Companion::HandleDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList)
{
    const auto deviceKey = status_.companionDeviceStatus.deviceKey;
    auto it = std::find_if(deviceStatusList.begin(), deviceStatusList.end(),
        [deviceKey](const DeviceStatus &status) { return status.deviceKey == deviceKey; });
    if (it != deviceStatusList.end()) {
        HandleDeviceStatusUpdate(*it);
        return;
    }
    HandleDeviceOffline();
}

void Companion::HandleDeviceStatusUpdate(const DeviceStatus &deviceStatus)
{
    if (status_.companionDeviceStatus == deviceStatus) {
        return;
    }

    status_.companionDeviceStatus = deviceStatus;
    IAM_LOGI("%{public}s device status updated", description_.c_str());

    if (!deviceStatus.isAuthMaintainActive) {
        IAM_LOGE("%{public}s auth maintain inactive, set token invalid", description_.c_str());
        SetCompanionTokenAtl(std::nullopt);
    }
    NotifySubscribers();
}

void Companion::HandleDeviceOffline()
{
    if (!status_.companionDeviceStatus.isOnline) {
        return;
    }

    status_.companionDeviceStatus.isOnline = false;
    IAM_LOGE("%{public}s device offline", description_.c_str());
    SetCompanionTokenAtl(std::nullopt);
    NotifySubscribers();
}

void Companion::SetEnabledBusinessIds(const std::vector<int32_t> &enabledBusinessIds)
{
    if (status_.enabledBusinessIds == enabledBusinessIds) {
        return;
    }

    status_.enabledBusinessIds = enabledBusinessIds;
    IAM_LOGI("%{public}s enabled business ids updated", description_.c_str());
    NotifySubscribers();
}

void Companion::SetCompanionValid(bool isValid)
{
    if (status_.isValid == isValid) {
        return;
    }

    IAM_LOGI("%{public}s set valid %{public}d -> %{public}d", description_.c_str(), status_.isValid, isValid);
    status_.isValid = isValid;
    NotifySubscribers();
}

void Companion::SetCompanionTokenAtl(std::optional<Atl> tokenAtl)
{
    std::optional<Atl> oldTokenAtl = status_.tokenAtl;
    status_.tokenAtl = tokenAtl;
    IAM_LOGI("%{public}s set token atl %{public}s -> %{public}s", description_.c_str(),
        GetOptionalString(oldTokenAtl).c_str(), GetOptionalString(tokenAtl).c_str());

    tokenTimeoutSubscription_.reset();
    if (!tokenAtl.has_value() && oldTokenAtl.has_value()) {
        HostRevokeTokenInput input = { status_.templateId };
        (void)GetSecurityAgent().HostRevokeToken(input);
    } else if (tokenAtl.has_value()) {
        tokenTimeoutSubscription_ = RelativeTimer::GetInstance().Register(
            [weakSelf = weak_from_this()]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                IAM_LOGI("%{public}s token timeout, revoking token", self->GetDescription().c_str());
                self->SetCompanionTokenAtl(std::nullopt);
            },
            TOKEN_TIMEOUT_MS);
        ENSURE_OR_RETURN(tokenTimeoutSubscription_ != nullptr);
        IAM_LOGI("%{public}s registered token timeout timer", description_.c_str());
    }

    if (status_.tokenAtl != tokenAtl) {
        NotifySubscribers();
    }
}

void Companion::RefreshTokenTimer()
{
    if (!status_.tokenAtl.has_value()) {
        IAM_LOGE("%{public}s no token atl, skip refresh timer", description_.c_str());
        return;
    }

    tokenTimeoutSubscription_.reset();
    tokenTimeoutSubscription_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            IAM_LOGI("%{public}s token timeout, revoking token", self->GetDescription().c_str());
            self->SetCompanionTokenAtl(std::nullopt);
        },
        TOKEN_TIMEOUT_MS);
    ENSURE_OR_RETURN(tokenTimeoutSubscription_ != nullptr);
    IAM_LOGI("%{public}s refreshed token timeout timer", description_.c_str());
}

void Companion::SetDeviceNames(const std::string &deviceName, const std::string &deviceUserName)
{
    if (status_.companionDeviceStatus.deviceName == deviceName &&
        status_.companionDeviceStatus.deviceUserName == deviceUserName) {
        return;
    }

    status_.companionDeviceStatus.deviceName = deviceName;
    status_.companionDeviceStatus.deviceUserName = deviceUserName;
    IAM_LOGI("%{public}s updating device names", description_.c_str());
    NotifySubscribers();
}

void Companion::NotifySubscribers()
{
    auto manager = managerWeakPtr_.lock();
    if (manager == nullptr) {
        IAM_LOGW("%{public}s manager is null, cannot notify subscribers", description_.c_str());
        return;
    }
    manager->NotifyCompanionStatusChange();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
