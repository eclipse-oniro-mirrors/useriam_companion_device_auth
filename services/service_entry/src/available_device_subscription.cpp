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

#include "available_device_subscription.h"

#include <new>

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_manager.h"
#include "cross_device_comm_manager.h"
#include "singleton_manager.h"
#include "subscription_manager.h"
#include "subscription_util.h"
#include "task_runner_manager.h"
#include "user_id_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

AvailableDeviceSubscription::AvailableDeviceSubscription(UserId userId,
    std::weak_ptr<SubscriptionManager> subscriptionManager)
    : userId_(userId),
      subscriptionManager_(subscriptionManager)
{
}

std::shared_ptr<AvailableDeviceSubscription> AvailableDeviceSubscription::Create(UserId userId,
    std::weak_ptr<SubscriptionManager> subscriptionManager)
{
    auto subscription = std::shared_ptr<AvailableDeviceSubscription>(
        new (std::nothrow) AvailableDeviceSubscription(userId, subscriptionManager));
    ENSURE_OR_RETURN_VAL(subscription != nullptr, nullptr);

    if (!subscription->Initialize()) {
        IAM_LOGE("initialize AvailableDeviceSubscription failed");
        return nullptr;
    }

    return subscription;
}

bool AvailableDeviceSubscription::Initialize()
{
    deviceStatusSubscription_ = GetCrossDeviceCommManager().SubscribeAllDeviceStatus(
        [weakSelf = weak_from_this()](const std::vector<DeviceStatus> &deviceStatusList) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDeviceStatusChange(deviceStatusList);
        });
    ENSURE_OR_RETURN_VAL(deviceStatusSubscription_ != nullptr, false);

    HandleDeviceStatusChange(GetCrossDeviceCommManager().GetAllDeviceStatus());
    return true;
}

UserId AvailableDeviceSubscription::GetUserId() const
{
    return userId_;
}

std::weak_ptr<AvailableDeviceSubscription> AvailableDeviceSubscription::GetWeakPtr()
{
    return weak_from_this();
}

void AvailableDeviceSubscription::OnCallbackAdded(const sptr<IIpcAvailableDeviceStatusCallback> &callback)
{
    ENSURE_OR_RETURN(callback != nullptr);
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [callback, cachedDeviceStatus = cachedAvailableDeviceStatus_]() {
            callback->OnAvailableDeviceStatusChange(cachedDeviceStatus);
        });
}

void AvailableDeviceSubscription::OnCallbackRemoteDied(const sptr<IIpcAvailableDeviceStatusCallback> &callback)
{
    ENSURE_OR_RETURN(callback != nullptr);
    TaskRunnerManager::GetInstance().PostTaskOnResident([callback, weakManager = subscriptionManager_]() {
        auto manager = weakManager.lock();
        ENSURE_OR_RETURN(manager != nullptr);
        manager->RemoveAvailableDeviceStatusCallback(callback);
    });
}

void AvailableDeviceSubscription::HandleDeviceStatusChange(const std::vector<DeviceStatus> &deviceStatusList)
{
    IAM_LOGI("HandleDeviceStatusChange start, total device count:%{public}zu, userId:%{public}d",
        deviceStatusList.size(), userId_);
    int32_t activeUserId = GetUserIdManager().GetActiveUserId();
    if (activeUserId != userId_) {
        IAM_LOGE("userId not match, activeUserId = %{public}d, userId_ = %{public}d", activeUserId, userId_);
        return;
    }

    std::vector<IpcDeviceStatus> availableDeviceStatus;
    availableDeviceStatus.reserve(deviceStatusList.size());
    for (const auto &deviceStatus : deviceStatusList) {
        if (GetCompanionManager().GetCompanionStatus(activeUserId, deviceStatus.deviceKey).has_value()) {
            continue;
        }
        availableDeviceStatus.push_back(ConvertToIpcDeviceStatus(deviceStatus));
    }

    if (IpcDeviceStatusVectorEqual(cachedAvailableDeviceStatus_, availableDeviceStatus)) {
        IAM_LOGI("Available device status not changed, skip notification");
        return;
    }

    cachedAvailableDeviceStatus_ = availableDeviceStatus;

    auto callbacks = callbacks_;

    IAM_LOGI("NotifyAvailableDeviceStatus start, callback count:%{public}zu, device count:%{public}zu",
        callbacks.size(), availableDeviceStatus.size());

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [callbacks = std::move(callbacks), availableDeviceStatus = std::move(availableDeviceStatus)]() {
            for (const auto &callback : callbacks) {
                ENSURE_OR_CONTINUE(callback != nullptr);
                IAM_LOGI("callback OnAvailableDeviceStatusChange");
                callback->OnAvailableDeviceStatusChange(availableDeviceStatus);
            }
        });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
