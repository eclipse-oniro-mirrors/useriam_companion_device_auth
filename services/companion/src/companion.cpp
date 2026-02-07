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

#include "adapter_manager.h"
#include "iam_safe_arithmetic.h"

#include "companion_manager_impl.h"
#include "relative_timer.h"
#include "scope_guard.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "time_keeper.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<Companion> Companion::Create(const PersistedCompanionStatus &persistedStatus, bool addedToIdm,
    const std::weak_ptr<CompanionManagerImpl> &managerWeakPtr)
{
    auto companion =
        std::shared_ptr<Companion>(new (std::nothrow) Companion(persistedStatus, addedToIdm, managerWeakPtr));
    ENSURE_OR_RETURN_DESC_VAL(companion->GetDescription(), companion != nullptr, nullptr);

    if (!companion->Initialize()) {
        IAM_LOGE("%{public}s failed to initialize", companion->GetDescription());
        return nullptr;
    }

    if (!addedToIdm) {
        companion->StartTemplateAddToIdmTimer();
    }

    IAM_LOGI("%{public}s created, addedToIdm=%{public}d", companion->GetDescription(), addedToIdm);
    return companion;
}

Companion::Companion(const PersistedCompanionStatus &persistedStatus, bool addedToIdm,
    const std::weak_ptr<CompanionManagerImpl> &managerWeakPtr)
    : addedToIdm_(addedToIdm),
      weakManager_(managerWeakPtr)
{
    status_.FromPersisted(persistedStatus);
    std::ostringstream oss;
    oss << "CdaCompanion(" << GET_TRUNCATED_STRING(status_.templateId) << ")";
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
                ENSURE_OR_RETURN_DESC(self->GetDescription(), self != nullptr);
                self->HandleDeviceStatusChanged(deviceStatusList);
            });
    ENSURE_OR_RETURN_DESC_VAL(GetDescription(), deviceStatusSubscription_ != nullptr, false);

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
    IAM_LOGI("%{public}s device status updated", GetDescription());

    if (!deviceStatus.isAuthMaintainActive) {
        IAM_LOGE("%{public}s auth maintain inactive, set token invalid", GetDescription());
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
    IAM_LOGE("%{public}s device offline", GetDescription());
    SetCompanionTokenAtl(std::nullopt);
    NotifySubscribers();
}

void Companion::SetEnabledBusinessIds(const std::vector<BusinessId> &enabledBusinessIds)
{
    if (status_.enabledBusinessIds == enabledBusinessIds) {
        return;
    }

    status_.enabledBusinessIds = enabledBusinessIds;
    IAM_LOGI("%{public}s enabled business ids updated", GetDescription());
    NotifySubscribers();
}

void Companion::SetCompanionValid(bool isValid)
{
    if (status_.isValid == isValid) {
        return;
    }

    IAM_LOGI("%{public}s set valid %{public}d -> %{public}d", GetDescription(), status_.isValid, isValid);
    status_.isValid = isValid;
    NotifySubscribers();
}

void Companion::SetCompanionTokenAtl(std::optional<Atl> tokenAtl)
{
    std::optional<Atl> oldTokenAtl = status_.tokenAtl;
    status_.tokenAtl = tokenAtl;
    IAM_LOGI("%{public}s set token atl %{public}s -> %{public}s", GetDescription(),
        GetOptionalString(oldTokenAtl).c_str(), GetOptionalString(tokenAtl).c_str());

    tokenTimeoutSubscription_.reset();
    if (!tokenAtl.has_value()) {
        HostRevokeTokenInput input = { status_.templateId };
        (void)GetSecurityAgent().HostRevokeToken(input);
    } else if (tokenAtl.has_value()) {
        tokenTimeoutSubscription_ = RelativeTimer::GetInstance().Register(
            [weakSelf = weak_from_this()]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN_DESC(self->GetDescription(), self != nullptr);
                IAM_LOGI("%{public}s token timeout, revoking token", self->GetDescription());
                self->SetCompanionTokenAtl(std::nullopt);
            },
            TOKEN_TIMEOUT_MS);
        ENSURE_OR_RETURN_DESC(GetDescription(), tokenTimeoutSubscription_ != nullptr);
        IAM_LOGI("%{public}s registered token timeout timer", GetDescription());
    }

    if (status_.tokenAtl != oldTokenAtl) {
        NotifySubscribers();
    }
}

void Companion::RefreshTokenTimer()
{
    if (!status_.tokenAtl.has_value()) {
        IAM_LOGE("%{public}s no token atl, skip refresh timer", GetDescription());
        return;
    }

    tokenTimeoutSubscription_.reset();
    tokenTimeoutSubscription_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN_DESC(self->GetDescription(), self != nullptr);
            IAM_LOGI("%{public}s token timeout, revoking token", self->GetDescription());
            self->SetCompanionTokenAtl(std::nullopt);
        },
        TOKEN_TIMEOUT_MS);
    ENSURE_OR_RETURN_DESC(GetDescription(), tokenTimeoutSubscription_ != nullptr);
    IAM_LOGI("%{public}s refreshed token timeout timer", GetDescription());
}

void Companion::SetDeviceNames(const std::string &deviceName, const std::string &deviceUserName)
{
    if (status_.companionDeviceStatus.deviceName == deviceName &&
        status_.companionDeviceStatus.deviceUserName == deviceUserName) {
        return;
    }

    status_.companionDeviceStatus.deviceName = deviceName;
    status_.companionDeviceStatus.deviceUserName = deviceUserName;
    IAM_LOGI("%{public}s updating device names", GetDescription());
    NotifySubscribers();
}

void Companion::NotifySubscribers()
{
    auto manager = weakManager_.lock();
    ENSURE_OR_RETURN_DESC(GetDescription(), manager != nullptr);
    manager->NotifyCompanionStatusChange();
}

void Companion::SetAddedToIdm(bool addedToIdm)
{
    if (addedToIdm_ == addedToIdm) {
        return;
    }

    IAM_LOGI("%{public}s change from %{public}d to %{public}d", GetDescription(), addedToIdm_, addedToIdm);
    addedToIdm_ = addedToIdm;
    if (addedToIdm) {
        templateAddToIdmTimer_.reset();
    }
}

void Companion::StartTemplateAddToIdmTimer()
{
    if (addedToIdm_) {
        IAM_LOGI("%{public}s already added to IDM, no need to start timer", GetDescription());
        return;
    }

    ScopeGuard guard([this]() {
        IAM_LOGE("%{public}s failed to start timer, triggering timeout handler", GetDescription());
        HandleTemplateAddToIdmTimeout();
    });

    IAM_LOGI("%{public}s starting template add timer, timeout: %{public}u ms", GetDescription(),
        IDM_ADD_TEMPLATE_TIMEOUT_MS);
    templateAddToIdmTimer_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN_DESC(self->GetDescription(), self != nullptr);
            self->HandleTemplateAddToIdmTimeout();
        },
        IDM_ADD_TEMPLATE_TIMEOUT_MS);
    ENSURE_OR_RETURN_DESC(GetDescription(), templateAddToIdmTimer_ != nullptr);
    guard.Cancel();
    return;
}

void Companion::HandleTemplateAddToIdmTimeout()
{
    if (addedToIdm_) {
        IAM_LOGI("%{public}s already added to IDM, timeout ignored", GetDescription());
        return;
    }

    IAM_LOGE("%{public}s template add to IDM failed", GetDescription());

    TemplateId templateId = status_.templateId;
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakManager = weakManager_, templateId]() {
        auto manager = weakManager.lock();
        if (manager == nullptr) {
            IAM_LOGE("manager is null when handling template add timeout");
            return;
        }
        manager->RemoveCompanion(templateId);
    });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
