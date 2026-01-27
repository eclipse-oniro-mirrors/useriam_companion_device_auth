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

#include <cinttypes>

#include "iam_check.h"
#include "iam_logger.h"

#include "channel_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "user_id_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<LocalDeviceStatusManager> LocalDeviceStatusManager::Create(std::shared_ptr<ChannelManager> channelMgr)
{
    auto manager = std::shared_ptr<LocalDeviceStatusManager>(new (std::nothrow) LocalDeviceStatusManager(channelMgr));
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);

    if (!manager->Initialize()) {
        IAM_LOGE("failed to initialize LocalDeviceStatusManager");
        return nullptr;
    }

    return manager;
}

LocalDeviceStatusManager::LocalDeviceStatusManager(std::shared_ptr<ChannelManager> channelMgr) : channelMgr_(channelMgr)
{
    profile_.protocols = { ProtocolId::VERSION_1 };
    profile_.hostSecureProtocols = { SecureProtocolId::DEFAULT };
    profile_.companionSecureProtocolId = SecureProtocolId::INVALID;
    profile_.capabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    profile_.protocolPriorityList = { ProtocolId::VERSION_1 };
    authState_.isAuthMaintainActive = false;
}

bool LocalDeviceStatusManager::Initialize()
{
    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, false);

    auto primaryChannel = channelMgr_->GetPrimaryChannel();
    ENSURE_OR_RETURN_VAL(primaryChannel != nullptr, false);

    auto weakSelf = weak_from_this();
    authMaintainSubscription_ = primaryChannel->SubscribeAuthMaintainActive([weakSelf](bool isActive) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->SetAuthMaintainActive(isActive);
    });
    ENSURE_OR_RETURN_VAL(authMaintainSubscription_ != nullptr, false);
    SetAuthMaintainActive(primaryChannel->GetAuthMaintainActive());

    profile_.companionSecureProtocolId = primaryChannel->GetCompanionSecureProtocolId();

    auto weakSelf2 = weak_from_this();
    activeUserIdSubscription_ = GetUserIdManager().SubscribeActiveUserId([weakSelf2](UserId userId) {
        auto self = weakSelf2.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnActiveUserIdChanged(userId);
    });
    ENSURE_OR_RETURN_VAL(activeUserIdSubscription_ != nullptr, false);
    OnActiveUserIdChanged(GetUserIdManager().GetActiveUserId());

    return true;
}

bool LocalDeviceStatusManager::IsAuthMaintainActive()
{
    return authState_.isAuthMaintainActive;
}

std::unique_ptr<Subscription> LocalDeviceStatusManager::SubscribeIsAuthMaintainActive(
    OnAuthMaintainActiveChange &&callback)
{
    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    statusSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGD("auth maintain active subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    // Notify current status immediately
    bool isActive = authState_.isAuthMaintainActive;
    TaskRunnerManager::GetInstance().PostTaskOnResident([callback, isActive]() {
        if (callback) {
            callback(isActive);
        }
    });

    auto weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->Unsubscribe(subscriptionId);
    });
}

std::map<ChannelId, DeviceKey> LocalDeviceStatusManager::GetLocalDeviceKeys()
{
    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, (std::map<ChannelId, DeviceKey> {}));
    std::map<ChannelId, DeviceKey> result;
    auto channels = channelMgr_->GetAllChannels();

    for (const auto &channel : channels) {
        ENSURE_OR_CONTINUE(channel != nullptr);
        auto deviceKeyOpt = GetLocalDeviceKey(channel->GetChannelId());
        if (deviceKeyOpt.has_value()) {
            result[channel->GetChannelId()] = deviceKeyOpt.value();
        }
    }

    return result;
}

std::optional<DeviceKey> LocalDeviceStatusManager::GetLocalDeviceKey(ChannelId channelId)
{
    ENSURE_OR_RETURN_VAL(channelMgr_ != nullptr, std::nullopt);
    auto channel = channelMgr_->GetChannelById(channelId);
    if (channel == nullptr) {
        IAM_LOGW("Channel not found: %{public}d", static_cast<int32_t>(channelId));
        return std::nullopt;
    }

    auto physicalKeyOpt = channel->GetLocalPhysicalDeviceKey();
    if (!physicalKeyOpt.has_value()) {
        IAM_LOGW("Failed to get physical device key for channel: %{public}d", static_cast<int32_t>(channelId));
        return std::nullopt;
    }

    const auto &physicalKey = physicalKeyOpt.value();
    DeviceKey deviceKey {};
    deviceKey.idType = physicalKey.idType;
    deviceKey.deviceId = physicalKey.deviceId;
    deviceKey.deviceUserId = GetUserIdManager().GetActiveUserId();

    return deviceKey;
}

LocalDeviceProfile LocalDeviceStatusManager::GetLocalDeviceProfile()
{
    return profile_;
}

void LocalDeviceStatusManager::SetAuthMaintainActive(bool isActive)
{
    authState_.isAuthMaintainActive = isActive;

    IAM_LOGI("auth maintain changed: active=%{public}d", isActive);

    NotifyStatusChange();
}

void LocalDeviceStatusManager::Unsubscribe(SubscribeId subscriptionId)
{
    statusSubscribers_.erase(subscriptionId);
    IAM_LOGD("auth maintain active subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
}

void LocalDeviceStatusManager::NotifyStatusChange()
{
    std::vector<std::function<void(bool)>> callbacks;
    callbacks.reserve(statusSubscribers_.size());
    for (const auto &pair : statusSubscribers_) {
        callbacks.emplace_back(pair.second);
    }
    bool isActive = authState_.isAuthMaintainActive;

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), isActive]() mutable {
        for (auto &cb : callbacks) {
            if (cb) {
                cb(isActive);
            }
        }
    });
}

void LocalDeviceStatusManager::OnActiveUserIdChanged(UserId userId)
{
    IAM_LOGI("active user id changed: userId=%{public}d", userId);
    NotifyStatusChange();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
