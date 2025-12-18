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

#include "template_status_subscription.h"

#include <new>
#include <vector>

#include "companion_manager.h"
#include "cross_device_comm_manager.h"
#include "errors.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "singleton_manager.h"
#include "subscription_util.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

TemplateStatusSubscription::TemplateStatusSubscription(UserId userId) : userId_(userId)
{
}

std::shared_ptr<TemplateStatusSubscription> TemplateStatusSubscription::Create(UserId userId)
{
    auto subscription =
        std::shared_ptr<TemplateStatusSubscription>(new (std::nothrow) TemplateStatusSubscription(userId));
    ENSURE_OR_RETURN_VAL(subscription != nullptr, nullptr);

    if (!subscription->Initialize()) {
        IAM_LOGE("initialize TemplateStatusSubscription failed");
        return nullptr;
    }

    return subscription;
}

UserId TemplateStatusSubscription::GetUserId() const
{
    return userId_;
}

std::weak_ptr<TemplateStatusSubscription> TemplateStatusSubscription::GetWeakPtr()
{
    return weak_from_this();
}

bool TemplateStatusSubscription::Initialize()
{
    auto weakSelf = std::weak_ptr<TemplateStatusSubscription>(shared_from_this());
    companionStatusSubscription_ = GetCompanionManager().SubscribeCompanionDeviceStatusChange(
        [weakSelf](const std::vector<CompanionStatus> &companionStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleCompanionStatusChange(companionStatusList);
        });
    if (companionStatusSubscription_ == nullptr) {
        IAM_LOGE("SubscribeCompanionDeviceStatusChange failed");
        return false;
    }

    auto companionStatusList = GetCompanionManager().GetAllCompanionStatus();
    HandleCompanionStatusChange(companionStatusList);
    return true;
}

void TemplateStatusSubscription::OnCallbackAdded(const sptr<IIpcTemplateStatusCallback> &callback)
{
    ENSURE_OR_RETURN(callback != nullptr);
    TaskRunnerManager::GetInstance().PostTaskOnResident([callback, cachedTemplateStatus = cachedTemplateStatus_]() {
        int32_t ret = callback->OnTemplateStatusChange(cachedTemplateStatus);
        if (ret != ERR_OK) {
            IAM_LOGE("OnTemplateStatusChange failed, ret %{public}d", ret);
        }
    });
}

void TemplateStatusSubscription::HandleCompanionStatusChange(const std::vector<CompanionStatus> &companionStatusList)
{
    IAM_LOGI("HandleCompanionStatusChange start, total companion status count:%{public}zu, userId:%{public}d",
        companionStatusList.size(), userId_);
    std::optional<int64_t> manageSubscribeTime = GetCrossDeviceCommManager().GetManageSubscribeTime();
    std::vector<IpcTemplateStatus> templateStatusList;
    templateStatusList.reserve(companionStatusList.size());

    for (const auto &status : companionStatusList) {
        if (status.hostUserId != userId_) {
            continue;
        }
        IAM_LOGI("companionStatus templateId: %{public}s, hostUserId: %{public}d, DeviceKey: %{public}s, channelId: "
                 "%{public}d, deviceModelInfo: %{public}s, deviceUserName: %{public}s, deviceName: %{public}s",
            GET_TRUNCATED_STRING(status.templateId).c_str(), status.hostUserId,
            status.companionDeviceStatus.deviceKey.GetDesc().c_str(),
            static_cast<int32_t>(status.companionDeviceStatus.channelId),
            status.companionDeviceStatus.deviceModelInfo.c_str(), status.companionDeviceStatus.deviceUserName.c_str(),
            status.companionDeviceStatus.deviceName.c_str());
        templateStatusList.push_back(ConvertToIpcTemplateStatus(status, manageSubscribeTime));
    }

    cachedTemplateStatus_ = templateStatusList;

    std::vector<sptr<IIpcTemplateStatusCallback>> callbacks;
    for (const auto &info : callbacks_) {
        if (info.callback != nullptr) {
            callbacks.push_back(info.callback);
        }
    }

    IAM_LOGI("NotifyTemplateStatus start, callback count:%{public}zu, template status count:%{public}zu",
        callbacks.size(), templateStatusList.size());

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), templateStatusList]() {
        for (const auto &callback : callbacks) {
            ENSURE_OR_CONTINUE(callback != nullptr);
            IAM_LOGI("callback OnTemplateStatusChange");
            int32_t ret = callback->OnTemplateStatusChange(templateStatusList);
            if (ret != ERR_OK) {
                IAM_LOGE("OnTemplateStatusChange failed, ret %{public}d", ret);
            }
        }
    });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
