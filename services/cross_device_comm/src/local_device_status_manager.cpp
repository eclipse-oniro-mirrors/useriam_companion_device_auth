/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "local_device_status_manager.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "channel_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<LocalDeviceStatusManager> LocalDeviceStatusManager::Create(std::shared_ptr<ChannelManager> channelMgr)
{
    auto manager = std::shared_ptr<LocalDeviceStatusManager>(new (std::nothrow) LocalDeviceStatusManager(channelMgr));
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);

    if (!manager->Init()) {
        IAM_LOGE("failed to initialize LocalDeviceStatusManager");
        return nullptr;
    }

    return manager;
}

LocalDeviceStatusManager::LocalDeviceStatusManager(std::shared_ptr<ChannelManager> channelMgr) : channelMgr_(channelMgr)
{
    localDeviceStatus_.protocols = { ProtocolId::VERSION_1 };
    localDeviceStatus_.hostSecureProtocols = { SecureProtocolId::DEFAULT };
    localDeviceStatus_.companionSecureProtocolId = SecureProtocolId::INVALID;
    localDeviceStatus_.capabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    localDeviceStatus_.protocolPriorityList = { ProtocolId::VERSION_1 };
    localDeviceStatus_.isAuthMaintainActive = false;
}

bool LocalDeviceStatusManager::Init()
{
    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, false);
    auto weakSelf = weak_from_this();
    auto channels = channelMgr_->GetAllChannels();
    for (const auto &channel : channels) {
        ENSURE_OR_RETURN_VAL(channel != nullptr, false);
        PhysicalDeviceKey physicalKey = channel->GetLocalPhysicalDeviceKey();
        DeviceKey deviceKey;
        deviceKey.idType = physicalKey.idType;
        deviceKey.deviceId = physicalKey.deviceId;
        deviceKey.deviceUserId = GetActiveUserIdManager().GetActiveUserId();
        localDeviceStatus_.channelId2DeviceKey[channel->GetChannelId()] = deviceKey;
    }

    auto primaryChannel = channelMgr_->GetPrimaryChannel();
    ENSURE_OR_RETURN_VAL(primaryChannel != nullptr, false);

    authMaintainSubscription_ = primaryChannel->SubscribeAuthMaintainActive([weakSelf](bool isActive) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->SetAuthMaintainActive(isActive);
    });
    ENSURE_OR_RETURN_VAL(authMaintainSubscription_ != nullptr, false);
    SetAuthMaintainActive(primaryChannel->GetAuthMaintainActive());

    localDeviceStatus_.companionSecureProtocolId = primaryChannel->GetcompanionSecureProtocolId();

    activeUserIdSubscription_ = GetActiveUserIdManager().SubscribeActiveUserId([weakSelf](UserId userId) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnActiveUserIdChanged(userId);
    });
    ENSURE_OR_RETURN_VAL(activeUserIdSubscription_ != nullptr, false);
    OnActiveUserIdChanged(GetActiveUserIdManager().GetActiveUserId());

    return true;
}

LocalDeviceStatus LocalDeviceStatusManager::GetLocalDeviceStatus()
{
    return localDeviceStatus_;
}

std::unique_ptr<Subscription> LocalDeviceStatusManager::SubscribeLocalDeviceStatus(OnLocalDeviceStatusChange &&callback)
{
    int32_t subscriptionId = nextSubscriptionId_++;
    statusSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGI("local device status subscription added: %{public}d", subscriptionId);

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->Unsubscribe(subscriptionId);
    });
}

void LocalDeviceStatusManager::SetAuthMaintainActive(bool isActive)
{
    localDeviceStatus_.isAuthMaintainActive = isActive;

    IAM_LOGI("auth maintain changed: active=%{public}d", isActive);

    NotifyStatusChange();
}

bool LocalDeviceStatusManager::isAuthMaintainActive()
{
    return localDeviceStatus_.isAuthMaintainActive;
}

void LocalDeviceStatusManager::Unsubscribe(int32_t subscriptionId)
{
    statusSubscribers_.erase(subscriptionId);
    IAM_LOGI("local device status subscription removed: %{public}d", subscriptionId);
}

void LocalDeviceStatusManager::NotifyStatusChange()
{
    std::vector<OnLocalDeviceStatusChange> callbacks;
    callbacks.reserve(statusSubscribers_.size());
    for (const auto &pair : statusSubscribers_) {
        callbacks.emplace_back(pair.second);
    }
    LocalDeviceStatus status = localDeviceStatus_;

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), status]() mutable {
        for (auto &cb : callbacks) {
            if (cb) {
                cb(status);
            }
        }
    });
}

void LocalDeviceStatusManager::OnActiveUserIdChanged(UserId userId)
{
    bool hasChanged = false;

    for (auto &pair : localDeviceStatus_.channelId2DeviceKey) {
        if (pair.second.deviceUserId != userId) {
            pair.second.deviceUserId = userId;
            hasChanged = true;
            IAM_LOGI("device key userId updated: channel=%{public}d, device=%{public}s, userId=%{public}d",
                static_cast<int32_t>(pair.first), pair.second.GetDesc().c_str(), userId);
        }
    }

    if (hasChanged) {
        NotifyStatusChange();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
