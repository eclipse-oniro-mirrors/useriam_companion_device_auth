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

#include "subscription_manager.h"

#include <map>
#include <memory>
#include <utility>

#include "iam_logger.h"

#include "available_device_subscription.h"
#include "continuous_auth_subscription.h"
#include "cross_device_comm_manager.h"
#include "cross_device_common.h"
#include "singleton_manager.h"
#include "template_status_subscription.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

SubscriptionManager::SubscriptionManager() = default;

std::shared_ptr<AvailableDeviceSubscription> SubscriptionManager::GetOrCreateAvailableDeviceSubscription(UserId userId)
{
    auto it = availableDeviceSubscriptions_.find(userId);
    if (it != availableDeviceSubscriptions_.end()) {
        return it->second;
    }

    auto subscription = AvailableDeviceSubscription::Create(userId, weak_from_this());
    if (subscription == nullptr) {
        IAM_LOGE("create AvailableDeviceSubscription failed");
        return nullptr;
    }
    availableDeviceSubscriptions_[userId] = subscription;
    subscription->SetDeathHandler(
        [weakThis = weak_from_this()](const sptr<IIpcAvailableDeviceStatusCallback> &callback) {
            auto self = weakThis.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->RemoveAvailableDeviceStatusCallback(callback);
        });
    return subscription;
}

std::shared_ptr<TemplateStatusSubscription> SubscriptionManager::GetOrCreateTemplateStatusSubscription(UserId userId)
{
    auto it = templateStatusSubscriptions_.find(userId);
    if (it != templateStatusSubscriptions_.end()) {
        return it->second;
    }

    auto subscription = TemplateStatusSubscription::Create(userId, weak_from_this());
    if (subscription == nullptr) {
        IAM_LOGE("create TemplateStatusSubscription failed");
        return nullptr;
    }
    templateStatusSubscriptions_[userId] = subscription;
    subscription->SetDeathHandler([weakThis = weak_from_this()](const sptr<IIpcTemplateStatusCallback> &callback) {
        auto self = weakThis.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->RemoveTemplateStatusCallback(callback);
    });
    return subscription;
}

std::shared_ptr<ContinuousAuthSubscription> SubscriptionManager::GetOrCreateContinuousAuthSubscription(UserId userId,
    std::optional<TemplateId> templateId)
{
    auto key = std::make_pair(userId, templateId);
    auto it = continuousAuthSubscriptions_.find(key);
    if (it != continuousAuthSubscriptions_.end()) {
        return it->second;
    }

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, weak_from_this());
    if (subscription == nullptr) {
        IAM_LOGE("create ContinuousAuthSubscription failed");
        return nullptr;
    }
    continuousAuthSubscriptions_[key] = subscription;
    subscription->SetDeathHandler(
        [weakThis = weak_from_this()](const sptr<IIpcContinuousAuthStatusCallback> &callback) {
            auto self = weakThis.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->RemoveContinuousAuthStatusCallback(callback);
        });
    return subscription;
}

void SubscriptionManager::AddAvailableDeviceStatusCallback(int32_t userId,
    const sptr<IIpcAvailableDeviceStatusCallback> &availableDeviceStatusCallback)
{
    if (availableDeviceStatusCallback == nullptr) {
        IAM_LOGE("availableDeviceStatusCallback is nullptr");
        return;
    }

    auto subscription = GetOrCreateAvailableDeviceSubscription(userId);
    ENSURE_OR_RETURN(subscription != nullptr);
    subscription->AddCallback(availableDeviceStatusCallback);
    UpdateSubscribeMode();
}

void SubscriptionManager::RemoveAvailableDeviceStatusCallback(
    const sptr<IIpcAvailableDeviceStatusCallback> &availableDeviceStatusCallback)
{
    if (availableDeviceStatusCallback == nullptr) {
        IAM_LOGE("availableDeviceStatusCallback is nullptr");
        return;
    }

    for (auto it = availableDeviceSubscriptions_.begin(); it != availableDeviceSubscriptions_.end();) {
        if (it->second != nullptr) {
            it->second->RemoveCallback(availableDeviceStatusCallback);
            if (!it->second->HasCallback()) {
                it = availableDeviceSubscriptions_.erase(it);
                continue;
            }
        }
        ++it;
    }
    UpdateSubscribeMode();
}

void SubscriptionManager::AddTemplateStatusCallback(int32_t userId,
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    if (templateStatusCallback == nullptr) {
        IAM_LOGE("templateStatusCallback is nullptr");
        return;
    }

    auto subscription = GetOrCreateTemplateStatusSubscription(userId);
    ENSURE_OR_RETURN(subscription != nullptr);
    subscription->AddCallback(templateStatusCallback);
    UpdateSubscribeMode();
}

void SubscriptionManager::RemoveTemplateStatusCallback(const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    if (templateStatusCallback == nullptr) {
        IAM_LOGE("templateStatusCallback is nullptr");
        return;
    }

    for (auto it = templateStatusSubscriptions_.begin(); it != templateStatusSubscriptions_.end();) {
        if (it->second != nullptr) {
            it->second->RemoveCallback(templateStatusCallback);
            if (!it->second->HasCallback()) {
                it = templateStatusSubscriptions_.erase(it);
                continue;
            }
        }
        ++it;
    }
    UpdateSubscribeMode();
}

void SubscriptionManager::AddContinuousAuthStatusCallback(int32_t userId, std::optional<uint64_t> templateId,
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    if (continuousAuthStatusCallback == nullptr) {
        IAM_LOGE("continuousAuthStatusCallback is nullptr");
        return;
    }

    auto subscription = GetOrCreateContinuousAuthSubscription(userId, templateId);
    ENSURE_OR_RETURN(subscription != nullptr);
    subscription->AddCallback(continuousAuthStatusCallback);
}

void SubscriptionManager::RemoveContinuousAuthStatusCallback(
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    if (continuousAuthStatusCallback == nullptr) {
        IAM_LOGE("continuousAuthStatusCallback is nullptr");
        return;
    }

    for (auto it = continuousAuthSubscriptions_.begin(); it != continuousAuthSubscriptions_.end();) {
        if (it->second != nullptr) {
            it->second->RemoveCallback(continuousAuthStatusCallback);
            if (!it->second->HasCallback()) {
                it = continuousAuthSubscriptions_.erase(it);
                continue;
            }
        }
        ++it;
    }
}

void SubscriptionManager::UpdateSubscribeMode()
{
    bool hasAvailableDeviceSubscriptions = !availableDeviceSubscriptions_.empty();
    bool hasTemplateStatusSubscriptions = !templateStatusSubscriptions_.empty();

    SubscribeMode mode = SUBSCRIBE_MODE_AUTH;
    if (hasAvailableDeviceSubscriptions || hasTemplateStatusSubscriptions) {
        mode = SUBSCRIBE_MODE_MANAGE;
    }

    GetCrossDeviceCommManager().SetSubscribeMode(mode);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
