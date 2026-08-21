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
#include <algorithm>
#include <map>
#include <memory>
#include <new>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "accesstoken_kit.h"
#include "adapter_manager.h"
#include "task_runner_manager.h"

#include "available_device_subscription.h"
#include "continuous_auth_subscription.h"
#include "cross_device_comm_manager.h"
#include "cross_device_common.h"
#include "singleton_manager.h"
#include "stale_subscription_monitor.h"
#include "template_status_subscription.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SUBSCRIPTION_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr size_t MAX_SUBSCRIPTIONS_PER_MAP = 100;
} // namespace

SubscriptionManager::CallerSubscription::CallerSubscription(const CallerInfo &callerInfo,
    std::weak_ptr<StaleSubscriptionMonitor> monitor, bool watchForeground)
    : callerType_(callerInfo.type)
{
    if (auto staleMonitor = monitor.lock()) {
        staleMonitorSub_ = staleMonitor->AddSubscription(callerInfo);
        if (staleMonitorSub_ == nullptr) {
            IAM_LOGE("AddSubscription to stale monitor failed, callerName:%{public}s", callerInfo.name.c_str());
        }
    }
    if (watchForeground && callerType_ == CallerTokenType::Hap) {
        bundleSub_ = GetAppForegroundStateAdapter().AddWatchedApp(callerInfo.name);
        if (bundleSub_ == nullptr) {
            IAM_LOGE("AddWatchedApp failed, callerName:%{public}s", callerInfo.name.c_str());
        }
    }
}

std::shared_ptr<SubscriptionManager> SubscriptionManager::Create()
{
    auto self = std::shared_ptr<SubscriptionManager>(new (std::nothrow) SubscriptionManager());
    ENSURE_OR_RETURN_VAL(self != nullptr, nullptr);
    if (!self->Init()) {
        IAM_LOGE("SubscriptionManager init failed");
        return nullptr;
    }
    return self;
}

bool SubscriptionManager::Init()
{
    staleSubscriptionMonitor_ = StaleSubscriptionMonitor::Create();
    ENSURE_OR_RETURN_VAL(staleSubscriptionMonitor_ != nullptr, false);
    return true;
}

std::shared_ptr<AvailableDeviceSubscription> SubscriptionManager::GetOrCreateAvailableDeviceSubscription(UserId userId)
{
    auto it = availableDeviceSubscriptions_.find(userId);
    if (it != availableDeviceSubscriptions_.end()) {
        return it->second;
    }

    if (availableDeviceSubscriptions_.size() >= MAX_SUBSCRIPTIONS_PER_MAP) {
        IAM_LOGE("availableDeviceSubscriptions limit reached (%{public}zu)", availableDeviceSubscriptions_.size());
        return nullptr;
    }

    auto subscription = AvailableDeviceSubscription::Create(userId, weak_from_this());
    ENSURE_OR_RETURN_VAL(subscription != nullptr, nullptr);
    availableDeviceSubscriptions_[userId] = subscription;
    subscription->SetDeathHandler(
        [weakSelf = weak_from_this()](const sptr<IIpcAvailableDeviceStatusCallback> &callback) {
            auto self = weakSelf.lock();
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

    if (templateStatusSubscriptions_.size() >= MAX_SUBSCRIPTIONS_PER_MAP) {
        IAM_LOGE("templateStatusSubscriptions limit reached (%{public}zu)", templateStatusSubscriptions_.size());
        return nullptr;
    }

    auto subscription = TemplateStatusSubscription::Create(userId, weak_from_this());
    ENSURE_OR_RETURN_VAL(subscription != nullptr, nullptr);
    templateStatusSubscriptions_[userId] = subscription;
    subscription->SetDeathHandler([weakSelf = weak_from_this()](const sptr<IIpcTemplateStatusCallback> &callback) {
        auto self = weakSelf.lock();
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

    if (continuousAuthSubscriptions_.size() >= MAX_SUBSCRIPTIONS_PER_MAP) {
        IAM_LOGE("continuousAuthSubscriptions limit reached (%{public}zu)", continuousAuthSubscriptions_.size());
        return nullptr;
    }

    auto subscription = ContinuousAuthSubscription::Create(userId, templateId, weak_from_this());
    ENSURE_OR_RETURN_VAL(subscription != nullptr, nullptr);
    continuousAuthSubscriptions_[key] = subscription;
    subscription->SetDeathHandler(
        [weakSelf = weak_from_this()](const sptr<IIpcContinuousAuthStatusCallback> &callback) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->RemoveContinuousAuthStatusCallback(callback);
        });
    return subscription;
}

ResultCode SubscriptionManager::AddAvailableDeviceStatusCallback(int32_t userId, CallerInfo callerInfo,
    const sptr<IIpcAvailableDeviceStatusCallback> &availableDeviceStatusCallback)
{
    if (availableDeviceStatusCallback == nullptr) {
        IAM_LOGE("availableDeviceStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    auto subscription = GetOrCreateAvailableDeviceSubscription(userId);
    ENSURE_OR_RETURN_VAL(subscription != nullptr, ResultCode::GENERAL_ERROR);
    subscription->AddCallback(availableDeviceStatusCallback);
    callerSubs_.insert_or_assign(availableDeviceStatusCallback->AsObject(),
        CallerSubscription(callerInfo, staleSubscriptionMonitor_, true));
    UpdateSubscribeMode();
    return ResultCode::SUCCESS;
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
    callerSubs_.erase(availableDeviceStatusCallback->AsObject());
    UpdateSubscribeMode();
}

ResultCode SubscriptionManager::AddTemplateStatusCallback(int32_t userId, CallerInfo callerInfo,
    const sptr<IIpcTemplateStatusCallback> &templateStatusCallback)
{
    if (templateStatusCallback == nullptr) {
        IAM_LOGE("templateStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    auto subscription = GetOrCreateTemplateStatusSubscription(userId);
    ENSURE_OR_RETURN_VAL(subscription != nullptr, ResultCode::GENERAL_ERROR);
    subscription->AddCallback(templateStatusCallback);
    callerSubs_.insert_or_assign(templateStatusCallback->AsObject(),
        CallerSubscription(callerInfo, staleSubscriptionMonitor_, false));
    UpdateSubscribeMode();
    GetCrossDeviceCommManager().SetTemplateStatusSubscribed(!templateStatusSubscriptions_.empty());
    return ResultCode::SUCCESS;
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
    callerSubs_.erase(templateStatusCallback->AsObject());
    UpdateSubscribeMode();
    GetCrossDeviceCommManager().SetTemplateStatusSubscribed(!templateStatusSubscriptions_.empty());
}

ResultCode SubscriptionManager::AddContinuousAuthStatusCallback(int32_t userId, std::optional<uint64_t> templateId,
    const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback)
{
    if (continuousAuthStatusCallback == nullptr) {
        IAM_LOGE("continuousAuthStatusCallback is nullptr");
        return ResultCode::INVALID_PARAMETERS;
    }

    auto subscription = GetOrCreateContinuousAuthSubscription(userId, templateId);
    ENSURE_OR_RETURN_VAL(subscription != nullptr, ResultCode::GENERAL_ERROR);
    subscription->AddCallback(continuousAuthStatusCallback);
    return ResultCode::SUCCESS;
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

bool SubscriptionManager::UpdateSubscribeMode()
{
    EnsureAppForegroundStateSubscribed();
    auto foregroundApps = GetAppForegroundStateAdapter().GetForegroundWatchedApps();
    SubscribeMode oldMode = GetCrossDeviceCommManager().GetSubscribeMode();
    SubscribeMode mode = !foregroundApps.empty() ? SUBSCRIBE_MODE_ALL_DEVICES : SUBSCRIBE_MODE_SUBSCRIBED_ONLY;
    IAM_LOGI("UpdateSubscribeMode mode:%{public}d foreground:%{public}s", static_cast<int32_t>(mode),
        GetVectorString(foregroundApps).c_str());
    GetCrossDeviceCommManager().SetSubscribeMode(mode);
    return (oldMode == SUBSCRIBE_MODE_SUBSCRIBED_ONLY && mode == SUBSCRIBE_MODE_ALL_DEVICES);
}

void SubscriptionManager::EnsureAppForegroundStateSubscribed()
{
    if (foregroundAppSub_) {
        return;
    }
    ForegroundWatchedAppsHandler handler = [weakSelf = weak_from_this()](const std::vector<std::string> &) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        if (self->UpdateSubscribeMode()) {
            TaskRunnerManager::GetInstance().PostTaskOnResident(
                []() { GetCrossDeviceCommManager().RefreshDeviceStatus(); });
        }
    };
    foregroundAppSub_ = GetAppForegroundStateAdapter().SubscribeForegroundWatchedApps(handler);
    if (!foregroundAppSub_) {
        IAM_LOGE("subscribe app foreground state failed");
        return;
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
