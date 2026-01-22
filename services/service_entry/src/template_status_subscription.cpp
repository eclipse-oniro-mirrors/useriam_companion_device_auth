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

#include "errors.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_manager.h"
#include "cross_device_comm_manager.h"
#include "singleton_manager.h"
#include "subscription_manager.h"
#include "subscription_util.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

TemplateStatusSubscription::TemplateStatusSubscription(UserId userId,
    std::weak_ptr<SubscriptionManager> subscriptionManager)
    : userId_(userId),
      subscriptionManager_(subscriptionManager)
{
}

std::shared_ptr<TemplateStatusSubscription> TemplateStatusSubscription::Create(UserId userId,
    std::weak_ptr<SubscriptionManager> subscriptionManager)
{
    auto subscription = std::shared_ptr<TemplateStatusSubscription>(
        new (std::nothrow) TemplateStatusSubscription(userId, subscriptionManager));
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

void TemplateStatusSubscription::OnCallbackRemoteDied(const sptr<IIpcTemplateStatusCallback> &callback)
{
    ENSURE_OR_RETURN(callback != nullptr);

    TaskRunnerManager::GetInstance().PostTaskOnResident([callback, weakManager = subscriptionManager_]() {
        auto manager = weakManager.lock();
        ENSURE_OR_RETURN(manager != nullptr);
        manager->RemoveTemplateStatusCallback(callback);
    });
}

void TemplateStatusSubscription::HandleCompanionStatusChange(const std::vector<CompanionStatus> &companionStatusList)
{
    IAM_LOGI("HandleCompanionStatusChange start, total companion status count:%{public}zu, userId:%{public}d",
        companionStatusList.size(), userId_);
    std::optional<SteadyTimeMs> manageSubscribeTime = GetCrossDeviceCommManager().GetManageSubscribeTime();
    std::vector<IpcTemplateStatus> templateStatusList;
    templateStatusList.reserve(companionStatusList.size());

    for (const auto &status : companionStatusList) {
        if (status.hostUserId != userId_) {
            continue;
        }
        templateStatusList.push_back(ConvertToIpcTemplateStatus(status, manageSubscribeTime));
    }

    if (IpcTemplateStatusVectorEqual(cachedTemplateStatus_, templateStatusList)) {
        IAM_LOGI("Template status not changed, skip notification");
        return;
    }

    cachedTemplateStatus_ = templateStatusList;

    auto callbacks = callbacks_;

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
