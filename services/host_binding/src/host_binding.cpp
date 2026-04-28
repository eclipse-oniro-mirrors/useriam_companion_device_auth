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

#include "host_binding.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "companion_manager.h"
#include "cross_device_comm_manager.h"
#include "host_binding_manager.h"
#include "relative_timer.h"
#include "request_factory.h"
#include "request_manager.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "subscription.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
HostBindingStatus BuildHostBindingStatus(const PersistedHostBindingStatus &persistedStatus)
{
    HostBindingStatus status = {};
    status.bindingId = persistedStatus.bindingId;
    status.companionUserId = persistedStatus.companionUserId;
    status.hostDeviceStatus.deviceKey = persistedStatus.hostDeviceKey;
    status.isTokenValid = persistedStatus.isTokenValid;
    return status;
}
} // namespace

std::shared_ptr<HostBinding> HostBinding::Create(const PersistedHostBindingStatus &persistedStatus)
{
    auto binding = std::shared_ptr<HostBinding>(new (std::nothrow) HostBinding(persistedStatus));
    ENSURE_OR_RETURN_VAL(binding != nullptr, nullptr);

    if (!binding->Initialize()) {
        IAM_LOGE("%{public}s failed to initialize", binding->GetDescription());
        return nullptr;
    }

    IAM_LOGI("%{public}s created", binding->GetDescription());
    return binding;
}

HostBinding::HostBinding(const PersistedHostBindingStatus &persistedStatus)
    : status_(BuildHostBindingStatus(persistedStatus))
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();

    std::ostringstream oss;
    oss << "CdaHost(B:" << GET_TRUNCATED_STRING(persistedStatus.bindingId)
        << ",D:" << GetTruncatedString(persistedStatus.hostDeviceKey.deviceId) << ")";
    description_ = oss.str();
}

HostBinding::~HostBinding()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    SetTokenValid(false, "host binding destroyed");
}

bool HostBinding::Initialize()
{
    deviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeDeviceStatus(status_.hostDeviceStatus.deviceKey,
        false, [weakSelf = weak_from_this()](const std::vector<DeviceStatus> &deviceStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDeviceStatusChanged(deviceStatusList);
        });
    if (deviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe device status", GetDescription());
        return false;
    }

    auto deviceStatusList = GetCrossDeviceCommManager().GetAllDeviceStatus();
    HandleDeviceStatusChanged(deviceStatusList);

    localDeviceStatusSubscription_ =
        GetCrossDeviceCommManager().SubscribeIsAuthMaintainActive([weakSelf = weak_from_this()](bool isActive) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleAuthMaintainActiveChanged(isActive);
        });
    if (localDeviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe auth maintain active", GetDescription());
        return false;
    }
    HandleAuthMaintainActiveChanged(GetCrossDeviceCommManager().IsAuthMaintainActive());

    return true;
}

void HostBinding::HandleDeviceStatusChanged(const std::vector<DeviceStatus> &deviceStatusList)
{
    auto hostDeviceKey = status_.hostDeviceStatus.deviceKey;
    auto it = std::find_if(deviceStatusList.begin(), deviceStatusList.end(),
        [hostDeviceKey](const auto &status) { return status.deviceKey == hostDeviceKey; });
    if (it != deviceStatusList.end()) {
        HandleHostDeviceStatusUpdate(*it);
        return;
    }
    HandleHostDeviceOffline();
}

void HostBinding::HandleHostDeviceStatusUpdate(const DeviceStatus &hostDeviceStatus)
{
    status_.hostDeviceStatus = hostDeviceStatus;
    IAM_LOGI("%{public}s device status updated", GetDescription());
}

void HostBinding::HandleHostDeviceOffline()
{
    if (!status_.hostDeviceStatus.isOnline) {
        return;
    }

    status_.hostDeviceStatus.isOnline = false;
    IAM_LOGE("%{public}s host device %{public}s is offline", GetDescription(),
        status_.hostDeviceStatus.deviceKey.GetDesc().c_str());
    SetTokenValid(false, "host device offline");
}

void HostBinding::HandleAuthMaintainActiveChanged(bool isActive)
{
    if (status_.localAuthMaintainActive == isActive) {
        return;
    }

    status_.localAuthMaintainActive = isActive;
    IAM_LOGI("%{public}s local auth maintain active -> %{public}d", GetDescription(), isActive);

    auto profile = GetCrossDeviceCommManager().GetLocalDeviceProfile();
    if (!profile.hostBindingRevokeTokenOnInactive) {
        IAM_LOGI("%{public}s skip revoke token on inactive due to configuration", GetDescription());
        return;
    }

    if (isActive) {
        authMaintainInactiveTimer_.reset();
        return;
    }

    auto delayMs = status_.hostDeviceStatus.atlRevokeDelayMs;
    if (!delayMs.has_value()) {
        return;
    }

    if (delayMs.value() == 0) {
        IAM_LOGI("%{public}s auth maintain inactive, immediate token revoke", GetDescription());
        SetTokenValid(false, "auth maintain inactive");
        return;
    }

    IAM_LOGI("%{public}s auth maintain inactive, scheduling token revoke in %{public}u ms", GetDescription(),
        delayMs.value());
    authMaintainInactiveTimer_ = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this()]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            IAM_LOGI("%{public}s auth maintain inactive timeout, revoking token", self->GetDescription());
            self->SetTokenValid(false, "auth maintain inactive");
        },
        delayMs.value());
}

void HostBinding::SetTokenValid(bool isTokenValid, const std::string &triggerReason)
{
    bool oldTokenValid = status_.isTokenValid;
    status_.isTokenValid = isTokenValid;
    IAM_LOGI("%{public}s set token valid %{public}s -> %{public}s", GetDescription(), GetBoolStr(oldTokenValid),
        GetBoolStr(isTokenValid));

    if (!isTokenValid && oldTokenValid) {
        CompanionRevokeTokenInput input = { status_.bindingId };
        (void)GetSecurityAgent().CompanionRevokeToken(input);

        const DeviceKey &hostDeviceKey = status_.hostDeviceStatus.deviceKey;
        auto request = GetRequestFactory().CreateCompanionRevokeTokenRequest(status_.companionUserId, hostDeviceKey,
            triggerReason);
        ENSURE_OR_RETURN_DESC(GetDescription(), request != nullptr);

        bool result = GetRequestManager().Start(request);
        if (!result) {
            IAM_LOGE("%{public}s failed to start CompanionRevokeTokenRequest", GetDescription());
            return;
        }

        IAM_LOGI("%{public}s successfully started CompanionRevokeTokenRequest", GetDescription());
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
