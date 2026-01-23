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

#include "continuous_auth_subscription.h"

#include <vector>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "companion_manager.h"
#include "singleton_manager.h"
#include "subscription_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

ContinuousAuthSubscription::ContinuousAuthSubscription(UserId userId, std::optional<TemplateId> templateId,
    std::weak_ptr<SubscriptionManager> subscriptionManager)
    : userId_(userId),
      templateId_(templateId),
      subscriptionManager_(subscriptionManager)
{
}

std::shared_ptr<ContinuousAuthSubscription> ContinuousAuthSubscription::Create(UserId userId,
    std::optional<TemplateId> templateId, std::weak_ptr<SubscriptionManager> subscriptionManager)
{
    auto subscription = std::shared_ptr<ContinuousAuthSubscription>(
        new (std::nothrow) ContinuousAuthSubscription(userId, templateId, subscriptionManager));
    ENSURE_OR_RETURN_VAL(subscription != nullptr, nullptr);

    if (!subscription->Initialize()) {
        IAM_LOGE("initialize ContinuousAuthSubscription failed");
        return nullptr;
    }

    return subscription;
}

bool ContinuousAuthSubscription::Initialize()
{
    IAM_LOGI("Initialize continuous auth subscription, userId:%{public}d, hasTemplateId:%{public}d", userId_,
        templateId_.has_value());

    companionStatusSubscription_ = GetCompanionManager().SubscribeCompanionDeviceStatusChange(
        [weakSelf = weak_from_this()](const std::vector<CompanionStatus> &companionStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleCompanionStatusChange(companionStatusList);
        });
    ENSURE_OR_RETURN_VAL(companionStatusSubscription_ != nullptr, false);

    auto companionStatusList = GetCompanionManager().GetAllCompanionStatus();
    HandleCompanionStatusChange(companionStatusList);

    IAM_LOGI("Initialize continuous auth subscription success");
    return true;
}

UserId ContinuousAuthSubscription::GetUserId() const
{
    return userId_;
}

std::optional<TemplateId> ContinuousAuthSubscription::GetTemplateId() const
{
    return templateId_;
}

std::weak_ptr<ContinuousAuthSubscription> ContinuousAuthSubscription::GetWeakPtr()
{
    return weak_from_this();
}

void ContinuousAuthSubscription::OnCallbackAdded(const sptr<IIpcContinuousAuthStatusCallback> &callback)
{
    ENSURE_OR_RETURN(callback != nullptr);

    std::optional<Atl> authTrustLevel = cachedAuthTrustLevel_;

    IpcContinuousAuthStatus status {};
    status.isAuthPassed = authTrustLevel.has_value();
    status.hasAuthTrustLevel = authTrustLevel.has_value();
    status.authTrustLevel = authTrustLevel.value_or(0);

    TaskRunnerManager::GetInstance().PostTaskOnResident([callback, status]() {
        int32_t ret = callback->OnContinuousAuthStatusChange(status);
        if (ret != ERR_OK) {
            IAM_LOGE("OnContinuousAuthStatusChange failed, ret %{public}d", ret);
        }
    });
}

void ContinuousAuthSubscription::OnCallbackRemoteDied(const sptr<IIpcContinuousAuthStatusCallback> &callback)
{
    ENSURE_OR_RETURN(callback != nullptr);

    TaskRunnerManager::GetInstance().PostTaskOnResident([callback, weakManager = subscriptionManager_]() {
        auto manager = weakManager.lock();
        ENSURE_OR_RETURN(manager != nullptr);
        manager->RemoveContinuousAuthStatusCallback(callback);
    });
}

void ContinuousAuthSubscription::HandleCompanionStatusChange(const std::vector<CompanionStatus> &companionStatusList)
{
    IAM_LOGI("HandleCompanionStatusChange, userId:%{public}d, hasTemplateId:%{public}d, total:%{public}zu", userId_,
        templateId_.has_value(), companionStatusList.size());

    std::optional<Atl> authTrustLevel = std::nullopt;

    for (const auto &status : companionStatusList) {
        if (status.hostUserId != userId_) {
            continue;
        }

        if (templateId_.has_value() && status.templateId != templateId_.value()) {
            continue;
        }

        if (status.isValid && status.tokenAtl.has_value()) {
            if (!authTrustLevel.has_value() || status.tokenAtl.value() > authTrustLevel.value()) {
                authTrustLevel = status.tokenAtl;
            }
        }
    }

    if (cachedAuthTrustLevel_ != authTrustLevel) {
        cachedAuthTrustLevel_ = authTrustLevel;
        NotifyAuthStatus(authTrustLevel);
    }
}

void ContinuousAuthSubscription::NotifyAuthStatus(std::optional<Atl> authTrustLevel)
{
    IAM_LOGI("Auth status changed, authTrustLevel:%{public}s", GetOptionalString(authTrustLevel).c_str());

    auto callbacks = callbacks_;

    IpcContinuousAuthStatus status {};
    status.isAuthPassed = authTrustLevel.has_value();
    status.hasAuthTrustLevel = authTrustLevel.has_value();
    status.authTrustLevel = authTrustLevel.value_or(0);

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), status]() {
        for (const auto &callback : callbacks) {
            ENSURE_OR_CONTINUE(callback != nullptr);
            IAM_LOGI("callback OnContinuousAuthStatusChange");
            int32_t ret = callback->OnContinuousAuthStatusChange(status);
            if (ret != ERR_OK) {
                IAM_LOGE("OnContinuousAuthStatusChange failed, ret %{public}d", ret);
            }
        }
    });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
