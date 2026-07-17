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
#include "iam_safe_arithmetic.h"

#include "adapter_manager.h"
#include "cda_scope_guard.h"
#include "companion_manager_impl.h"
#include "relative_timer.h"
#include "security_agent.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "time_keeper.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_COMPANION

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<Companion> Companion::Create(const PersistedCompanionStatus &persistedStatus, bool addedToIdm,
    const std::weak_ptr<CompanionManagerImpl> &managerWeakPtr)
{
    auto companion =
        std::shared_ptr<Companion>(new (std::nothrow) Companion(persistedStatus, addedToIdm, managerWeakPtr));
    ENSURE_OR_RETURN_VAL(companion != nullptr, nullptr);

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
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    status_.FromPersisted(persistedStatus);
    description_ = BuildDescription(status_);
}

Companion::~Companion()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    IAM_LOGI("%{public}s destroyed", GetDescription());
    SetCompanionTokenAuthAtl(std::nullopt);
}

std::string Companion::BuildDescription(const CompanionStatus &status)
{
    std::ostringstream oss;
    oss << "CdaCompanion(T:" << GET_TRUNCATED_STRING(status.templateId)
        << ",D:" << GetTruncatedString(status.companionDeviceStatus.deviceKey.deviceId) << ")";
    return oss.str();
}

bool Companion::Initialize()
{
    deviceStatusSubscription_ =
        GetCrossDeviceCommManager().SubscribeDeviceStatus(status_.companionDeviceStatus.deviceKey, true,
            [weakSelf = weak_from_this()](const std::vector<DeviceStatus> &deviceStatusList) {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
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

    HandleAuthMaintainActiveChanged(deviceStatus);
    HandleCompanionStatusChange(deviceStatus);
    status_.companionDeviceStatus = deviceStatus;
    IAM_LOGI("%{public}s device status updated", GetDescription());
    NotifySubscribers();
}

void Companion::HandleDeviceOffline()
{
    if (!status_.companionDeviceStatus.isOnline) {
        return;
    }

    IAM_LOGE("%{public}s device offline", GetDescription());
    status_.companionDeviceStatus.isOnline = false;
    authMaintainInactiveTimer_.reset();
    SetCompanionTokenAuthAtl(std::nullopt);
    NotifySubscribers();
}

void Companion::HandleAuthMaintainActiveChanged(const DeviceStatus &deviceStatus)
{
    bool oldActive = status_.companionDeviceStatus.isAuthMaintainActive;
    if (oldActive == deviceStatus.isAuthMaintainActive) {
        return;
    }

    IAM_LOGI("%{public}s isAuthMaintainActive changed: %{public}d -> %{public}d", GetDescription(), oldActive,
        deviceStatus.isAuthMaintainActive);

    if (deviceStatus.isAuthMaintainActive) {
        authMaintainInactiveTimer_.reset();
        return;
    }

    if (!status_.tokenAuthAtl.has_value()) {
        return;
    }

    auto delayMs = deviceStatus.atlRevokeDelayMs;
    if (!delayMs.has_value()) {
        return;
    }

    if (delayMs.value() == 0) {
        IAM_LOGI("%{public}s auth maintain inactive, immediate atl revoke", GetDescription());
        SetCompanionTokenAuthAtl(std::nullopt);
        return;
    }

    IAM_LOGI("%{public}s auth maintain inactive, scheduling atl revoke in %{public}u ms", GetDescription(),
        delayMs.value());
    authMaintainInactiveTimer_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            IAM_LOGI("%{public}s auth maintain inactive timeout, revoking atl", self->GetDescription());
            self->SetCompanionTokenAuthAtl(std::nullopt);
        },
        delayMs.value());
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

void Companion::SetCompanionTokenAuthAtl(std::optional<Atl> tokenAuthAtl, bool forEnrollment)
{
    std::optional<Atl> oldTokenAuthAtl = status_.tokenAuthAtl;
    status_.tokenAuthAtl = tokenAuthAtl;
    IAM_LOGI("%{public}s set token auth atl %{public}s -> %{public}s", GetDescription(),
        GetOptionalString(oldTokenAuthAtl).c_str(), GetOptionalString(tokenAuthAtl).c_str());

    tokenTimeoutSubscription_.reset();
    if (oldTokenAuthAtl.has_value() && !tokenAuthAtl.has_value()) {
        authMaintainInactiveTimer_.reset();
        HostRevokeTokenInput input = { status_.templateId };
        (void)GetSecurityAgent().HostRevokeToken(input);
    } else if (tokenAuthAtl.has_value()) {
        tokenTimeoutSubscription_ = RelativeTimer::GetInstance().Register(
            [weakSelf = weak_from_this()]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                IAM_LOGI("%{public}s token timeout, revoking token", self->GetDescription());
                self->SetCompanionTokenAuthAtl(std::nullopt);
            },
            TOKEN_TIMEOUT_MS);
        ENSURE_OR_RETURN_DESC(GetDescription(), tokenTimeoutSubscription_ != nullptr);
        IAM_LOGI("%{public}s registered token timeout timer", GetDescription());

        if (forEnrollment && !status_.companionDeviceStatus.isAuthMaintainActive) {
            IAM_LOGI("%{public}s device not worn when enroll, start %{public}u ms timer", GetDescription(),
                TOKEN_ENROLL_NOT_WORN_TIMEOUT_MS);
            authMaintainInactiveTimer_ = RelativeTimer::GetInstance().Register(
                [weakSelf = weak_from_this()]() {
                    auto self = weakSelf.lock();
                    ENSURE_OR_RETURN(self != nullptr);
                    IAM_LOGI("%{public}s enroll not worn timeout, revoking token", self->GetDescription());
                    self->SetCompanionTokenAuthAtl(std::nullopt);
                },
                TOKEN_ENROLL_NOT_WORN_TIMEOUT_MS);
        }
    }

    if (status_.tokenAuthAtl != oldTokenAuthAtl) {
        NotifySubscribers();
    }
}

void Companion::HandleCompanionStatusChange(const DeviceStatus &deviceStatus)
{
    const auto &oldStatus = status_.companionDeviceStatus;
    if (oldStatus.deviceModelInfo == deviceStatus.deviceModelInfo && oldStatus.deviceName == deviceStatus.deviceName &&
        oldStatus.deviceUserName == deviceStatus.deviceUserName) {
        return;
    }

    HostUpdateCompanionStatusInput input { .templateId = status_.templateId,
        .companionDeviceModelInfo = deviceStatus.deviceModelInfo,
        .companionDeviceName = deviceStatus.deviceName,
        .companionDeviceUserName = deviceStatus.deviceUserName };
    ResultCode ret = GetSecurityAgent().HostUpdateCompanionStatus(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s HostUpdateCompanionStatus failed ret %{public}d", GetDescription(), ret);
        return;
    }
    IAM_LOGI("%{public}s update companion status success", GetDescription());
}

void Companion::NotifySubscribers()
{
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakManager = weakManager_]() {
        auto manager = weakManager.lock();
        ENSURE_OR_RETURN(manager != nullptr);
        manager->NotifyCompanionStatusChange();
    });
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
    NotifySubscribers();
}

void Companion::StartTemplateAddToIdmTimer()
{
    if (addedToIdm_) {
        IAM_LOGI("%{public}s already added to IDM, no need to start timer", GetDescription());
        return;
    }

    ScopeGuard guard([weakSelf = weak_from_this()]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        IAM_LOGE("%{public}s failed to start timer, triggering timeout handler", self->GetDescription());
        self->HandleTemplateAddToIdmTimeout();
    });

    IAM_LOGI("%{public}s starting template add timer, timeout: %{public}u ms", GetDescription(),
        IDM_ADD_TEMPLATE_TIMEOUT_MS);
    templateAddToIdmTimer_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
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
            IAM_LOGE("manager is null when handling template add timeout for templateId %{public}s",
                GET_MASKED_NUM_CSTR(templateId));
            return;
        }
        manager->RemoveCompanion(templateId, true);
    });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
