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
#include "iam_ptr.h"

#include "cross_device_comm_manager.h"
#include "host_binding_manager.h"
#include "relative_timer.h"
#include "request_factory.h"
#include "request_manager.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "subscription.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<HostBinding> HostBinding::Create(const PersistedHostBindingStatus &persistedStatus)
{
    auto binding = std::shared_ptr<HostBinding>(new (std::nothrow) HostBinding(persistedStatus));
    ENSURE_OR_RETURN_VAL(binding != nullptr, nullptr);

    if (!binding->Initialize()) {
        IAM_LOGE("%{public}s failed to initialize", binding->GetDescription().c_str());
        return nullptr;
    }

    IAM_LOGI("%{public}s created", binding->GetDescription().c_str());
    return binding;
}

HostBinding::HostBinding(const PersistedHostBindingStatus &persistedStatus)
{
    status_.bindingId = persistedStatus.bindingId;
    status_.companionUserId = persistedStatus.companionUserId;
    status_.hostDeviceStatus.deviceKey = persistedStatus.hostDeviceKey;
    status_.isTokenValid = persistedStatus.isTokenValid;

    std::ostringstream oss;
    oss << "HB_" << GET_TRUNCATED_STRING(persistedStatus.bindingId);
    description_ = oss.str();
}

HostBinding::~HostBinding()
{
    SetTokenValid(false);
}

bool HostBinding::Initialize()
{
    deviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeDeviceStatus(status_.hostDeviceStatus.deviceKey,
        [weakSelf = weak_from_this()](const std::vector<DeviceStatus> &deviceStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDeviceStatusChanged(deviceStatusList);
        });
    if (deviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe device status", GetDescription().c_str());
        return false;
    }

    auto devcieStatusList = GetCrossDeviceCommManager().GetAllDeviceStatus();
    HandleDeviceStatusChanged(devcieStatusList);

    localDeviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeLocalDeviceStatus(
        [weakSelf = weak_from_this()](const LocalDeviceStatus &localDeviceStatus) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleLocalDeviceStatusChanged(localDeviceStatus);
        });
    if (localDeviceStatusSubscription_ == nullptr) {
        IAM_LOGE("%{public}s failed to subscribe local device status", GetDescription().c_str());
        return false;
    }
    HandleLocalDeviceStatusChanged(GetCrossDeviceCommManager().GetLocalDeviceStatus());

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
    IAM_LOGI("%{public}s device status updated", description_.c_str());
}

void HostBinding::HandleHostDeviceOffline()
{
    if (!status_.hostDeviceStatus.isOnline) {
        return;
    }

    status_.hostDeviceStatus.isOnline = false;
    IAM_LOGE("host device %{public}s is offline", status_.hostDeviceStatus.deviceKey.GetDesc().c_str());
    SetTokenValid(false);
}

void HostBinding::HandleLocalDeviceStatusChanged(const LocalDeviceStatus &localDeviceStatus)
{
    if (status_.localAuthMaintainActive == localDeviceStatus.isAuthMaintainActive) {
        return;
    }

    status_.localAuthMaintainActive = localDeviceStatus.isAuthMaintainActive;
    IAM_LOGI("%{public}s local auth maintain active -> %{public}d", description_.c_str(),
        localDeviceStatus.isAuthMaintainActive);
    if (!localDeviceStatus.isAuthMaintainActive) {
        IAM_LOGE("%{public}s local auth maintain inactive, revoking token", description_.c_str());
        SetTokenValid(false);
    }
}

void HostBinding::SetTokenValid(bool isTokenValid)
{
    bool oldTokenValid = status_.isTokenValid;
    status_.isTokenValid = isTokenValid;
    IAM_LOGI("%{public}s set token valid %{public}s -> %{public}s", description_.c_str(), GetBoolStr(oldTokenValid),
        GetBoolStr(isTokenValid));

    tokenTimeoutSubscription_.reset();
    if (!isTokenValid && oldTokenValid) {
        CompanionRevokeTokenInput input = { status_.bindingId };
        (void)GetSecurityAgent().CompanionRevokeToken(input);

        const DeviceKey &hostDeviceKey = status_.hostDeviceStatus.deviceKey;
        auto request = GetRequestFactory().CreateCompanionRevokeTokenRequest(status_.companionUserId, hostDeviceKey);
        ENSURE_OR_RETURN(request != nullptr);

        bool result = GetRequestManager().Start(request);
        if (!result) {
            IAM_LOGE("%{public}s failed to start CompanionRevokeTokenRequest", description_.c_str());
            return;
        }

        IAM_LOGI("%{public}s successfully started CompanionRevokeTokenRequest", description_.c_str());
    } else if (isTokenValid) {
        tokenTimeoutSubscription_ = RelativeTimer::GetInstance().Register(
            [weakSelf = weak_from_this()]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                IAM_LOGI("%{public}s token timeout, revoking token", self->GetDescription().c_str());
                self->SetTokenValid(false);
            },
            TOKEN_TIMEOUT_MS);
        ENSURE_OR_RETURN(tokenTimeoutSubscription_ != nullptr);
        IAM_LOGI("%{public}s registered token timeout timer", description_.c_str());
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
