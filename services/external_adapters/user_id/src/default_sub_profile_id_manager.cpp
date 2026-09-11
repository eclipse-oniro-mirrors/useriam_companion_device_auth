/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "os_account_subprofile_client.h"
#include "os_account_sub_profile_subscribe_callback.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "sa_status_listener.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "sub_profile_id_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_DEFAULT_SUB_PROFILE_ID_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class DefaultSubProfileIdManager final
    : public std::enable_shared_from_this<DefaultSubProfileIdManager>, public ISubProfileIdManager {
public:
    DefaultSubProfileIdManager();
    ~DefaultSubProfileIdManager() override;

    int32_t GetForegroundSubProfileId(UserId userId) const override;
    bool IsForegroundSubProfileId(UserId userId, int32_t subProfileId) const override;
    std::optional<std::string> GetSubProfileName(UserId userId, int32_t subProfileId) const override;
    std::unique_ptr<Subscription> SubscribeSubProfileChanged(SubProfileChangedCallback &&callback) override;

private:
    class SubProfileEventSubscriber final : public AccountSA::OsAccountSubProfileSubscribeCallback {
    public:
        explicit SubProfileEventSubscriber(std::weak_ptr<DefaultSubProfileIdManager> impl);
        ~SubProfileEventSubscriber() override = default;

        void OnSubProfileChanged(const AccountSA::SubProfileEventData &eventData) override;

    private:
        std::weak_ptr<DefaultSubProfileIdManager> impl_;
    };

    friend class ISubProfileIdManager;

    bool Initialize();
    void HandleOsAccountServiceReady();
    void HandleOsAccountServiceUnavailable();
    void SubscribeSubProfileEvent();
    void UnsubscribeSubProfileEvent();
    void OnSubProfileChanged(const AccountSA::SubProfileEventData &eventData);
    void NotifySubProfileChangedSubscribers(UserId userId, int32_t subProfileId, SubProfileEventType eventType);
    void UnsubscribeSubProfileChanged(const SubscribeId &subscribeId);

    bool initialized_ = false;
    std::unique_ptr<SaStatusListener> saStatusListener_;
    std::shared_ptr<SubProfileEventSubscriber> subProfileEventSubscriber_;
    std::map<SubscribeId, SubProfileChangedCallback> subProfileChangedSubscribers_;
};

DefaultSubProfileIdManager::DefaultSubProfileIdManager()
{
}

DefaultSubProfileIdManager::~DefaultSubProfileIdManager()
{
    UnsubscribeSubProfileEvent();
}

bool DefaultSubProfileIdManager::Initialize()
{
    constexpr const char *osAccountSaName = "OsAccountService";
    {
        if (initialized_) {
            IAM_LOGI("already initialized");
            return true;
        }

        std::weak_ptr<DefaultSubProfileIdManager> weakImpl = weak_from_this();

        saStatusListener_ = SaStatusListener::Create(
            osAccountSaName, SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN,
            [weakImpl]() {
                auto impl = weakImpl.lock();
                if (impl == nullptr) {
                    IAM_LOGE("manager destroyed, ignore service ready event");
                    return;
                }
                impl->HandleOsAccountServiceReady();
            },
            [weakImpl]() {
                auto impl = weakImpl.lock();
                if (impl == nullptr) {
                    IAM_LOGE("manager destroyed, ignore service unavailable event");
                    return;
                }
                impl->HandleOsAccountServiceUnavailable();
            });
        if (saStatusListener_ == nullptr) {
            IAM_LOGE("failed to subscribe SA status");
            return false;
        }
        initialized_ = true;
    }
    return true;
}


void DefaultSubProfileIdManager::HandleOsAccountServiceReady()
{
    IAM_LOGI("start");
    SubscribeSubProfileEvent();
}

void DefaultSubProfileIdManager::HandleOsAccountServiceUnavailable()
{
    IAM_LOGI("start");
    UnsubscribeSubProfileEvent();
}

int32_t DefaultSubProfileIdManager::GetForegroundSubProfileId(UserId userId) const
{
    int32_t subProfileId = INVALID_SUB_PROFILE_ID;
    ErrCode errCode =
        AccountSA::OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(userId, subProfileId);
    if (errCode != ERR_OK) {
        IAM_LOGE("GetOsAccountForegroundSubProfileId failed, err:%{public}d", errCode);
        return INVALID_SUB_PROFILE_ID;
    }
    IAM_LOGI("GetForegroundSubProfileId success, subProfileId:%{public}d", subProfileId);
    return subProfileId;
}

bool DefaultSubProfileIdManager::IsForegroundSubProfileId(UserId userId, int32_t subProfileId) const
{
    if (subProfileId == INVALID_SUB_PROFILE_ID) {
        IAM_LOGE("sub profile id is invalid");
        return false;
    }
    int32_t foregroundSubProfileId = GetForegroundSubProfileId(userId);
    if (foregroundSubProfileId == INVALID_SUB_PROFILE_ID) {
        IAM_LOGE("failed to get foreground sub profile id for userId=%{public}d", userId);
        return false;
    }
    return subProfileId == foregroundSubProfileId;
}

std::optional<std::string> DefaultSubProfileIdManager::GetSubProfileName(UserId userId, int32_t subProfileId) const
{
    if (subProfileId == INVALID_SUB_PROFILE_ID) {
        IAM_LOGE("sub profile id is invalid");
        return std::nullopt;
    }
    AccountSA::OsAccountSubspaceResult subspaceResult;
    AccountSA::OhosAccountInfo distributedInfo;
    ErrCode errCode = AccountSA::OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(
        userId, subProfileId, subspaceResult, distributedInfo);
    if (errCode != ERR_OK) {
        IAM_LOGE("GetOsAccountSubProfile failed %{public}d for userId=%{public}d subProfileId=%{public}d",
            errCode, userId, subProfileId);
        return std::nullopt;
    }
    if (distributedInfo.nickname_.empty()) {
        IAM_LOGI("sub profile nickname is empty for userId=%{public}d subProfileId=%{public}d", userId, subProfileId);
        return std::nullopt;
    }
    return distributedInfo.nickname_;
}

void DefaultSubProfileIdManager::SubscribeSubProfileEvent()
{
    if (subProfileEventSubscriber_ != nullptr) {
        IAM_LOGI("already subscribed to sub profile event");
        return;
    }

    auto subscriber = std::make_shared<SubProfileEventSubscriber>(weak_from_this());
    ENSURE_OR_RETURN(subscriber != nullptr);

    std::set<AccountSA::OsAccountSubProfileEventType> types = {
        AccountSA::OsAccountSubProfileEventType::SWITCHED,
        AccountSA::OsAccountSubProfileEventType::DELETED,
    };
    ErrCode errCode = AccountSA::OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(
        types, subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("SubscribeOsAccountSubProfileEvents failed %{public}d", errCode);
        return;
    }
    subProfileEventSubscriber_ = subscriber;
    IAM_LOGI("SubscribeOsAccountSubProfileEvents success");
}

void DefaultSubProfileIdManager::UnsubscribeSubProfileEvent()
{
    if (subProfileEventSubscriber_ == nullptr) {
        return;
    }
    auto subscriber = subProfileEventSubscriber_;
    subProfileEventSubscriber_.reset();

    ErrCode errCode = AccountSA::OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(
        subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("UnsubscribeOsAccountSubProfileEvents failed %{public}d", errCode);
    }
}

void DefaultSubProfileIdManager::OnSubProfileChanged(const AccountSA::SubProfileEventData &eventData)
{
    IAM_LOGI("sub profile changed, type=%{public}d, osAccountId=%{public}d, subProfileId=%{public}d, "
             "previousSubProfileId=%{public}d",
        static_cast<int32_t>(eventData.type_), eventData.osAccountId_, eventData.subProfileId_,
        eventData.previousSubProfileId_);

    SubProfileEventType eventType = SubProfileEventType::SWITCHED;
    if (eventData.type_ == AccountSA::OsAccountSubProfileEventType::DELETED) {
        eventType = SubProfileEventType::DELETED;
    }
    NotifySubProfileChangedSubscribers(eventData.osAccountId_, eventData.subProfileId_, eventType);
}

void DefaultSubProfileIdManager::NotifySubProfileChangedSubscribers(UserId userId, int32_t subProfileId,
    SubProfileEventType eventType)
{
    std::vector<SubProfileChangedCallback> callbacks;
    for (const auto &entry : subProfileChangedSubscribers_) {
        callbacks.emplace_back(entry.second);
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [callbacks = std::move(callbacks), userId, subProfileId, eventType]() {
            for (const auto &callback : callbacks) {
                if (callback != nullptr) {
                    callback(userId, subProfileId, eventType);
                }
            }
        });
}

std::unique_ptr<Subscription> DefaultSubProfileIdManager::SubscribeSubProfileChanged(
    SubProfileChangedCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);
    SubscribeId subscribeId = GetMiscManager().GetNextGlobalId();
    subProfileChangedSubscribers_[subscribeId] = std::move(callback);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscribeId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeSubProfileChanged(subscribeId);
    });
}

void DefaultSubProfileIdManager::UnsubscribeSubProfileChanged(const SubscribeId &subscribeId)
{
    subProfileChangedSubscribers_.erase(subscribeId);
}

DefaultSubProfileIdManager::SubProfileEventSubscriber::SubProfileEventSubscriber(
    std::weak_ptr<DefaultSubProfileIdManager> impl)
    : impl_(std::move(impl))
{
}

void DefaultSubProfileIdManager::SubProfileEventSubscriber::OnSubProfileChanged(
    const AccountSA::SubProfileEventData &eventData)
{
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakImpl = impl_, eventData]() {
        auto impl = weakImpl.lock();
        if (impl == nullptr) {
            IAM_LOGE("manager has been destroyed, ignore sub profile changed event");
            return;
        }
        impl->OnSubProfileChanged(eventData);
    });
}

#ifndef ENABLE_TEST
std::shared_ptr<ISubProfileIdManager> ISubProfileIdManager::Create()
{
    auto manager = std::make_shared<DefaultSubProfileIdManager>();
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    if (!manager->Initialize()) {
        IAM_LOGE("failed to init default sub profile id manager");
        return nullptr;
    }
    return manager;
}
#endif // ENABLE_TEST

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
