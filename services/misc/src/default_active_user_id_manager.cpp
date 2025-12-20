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

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "os_account_manager.h"
#include "os_account_subscribe_info.h"
#include "os_account_subscriber.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "sa_status_listener.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class DefaultActiveUserIdManager final : public IActiveUserIdManager,
                                         public std::enable_shared_from_this<DefaultActiveUserIdManager> {
public:
    DefaultActiveUserIdManager();
    ~DefaultActiveUserIdManager() override;

    bool Initialize() override;
    UserId GetActiveUserId() const override;
    std::string GetActiveUserName() const override;
    std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) override;

private:
    class ActiveUserOsAccountSubscriber final : public AccountSA::OsAccountSubscriber {
    public:
        ActiveUserOsAccountSubscriber(const AccountSA::OsAccountSubscribeInfo &subscribeInfo,
            std::weak_ptr<DefaultActiveUserIdManager> impl);
        ~ActiveUserOsAccountSubscriber() override = default;

        void OnStateChanged(const AccountSA::OsAccountStateData &data) override;

    private:
        std::weak_ptr<DefaultActiveUserIdManager> impl_;
    };

    void HandleOsAccountServiceReady();
    void HandleOsAccountServiceUnavailable();
    void SubscribeOsAccount();
    void UnsubscribeOsAccount();
    void OnOsAccountStateChange(const AccountSA::OsAccountStateData &data);
    void SyncActiveUserId();
    void UpdateActiveUserId(UserId userId);
    void NotifySubscribers(UserId userId);
    int32_t QueryActiveUserIdFromSystem() const;
    void UnsubscribeActiveUserId(const SubscribeId &subscribeId);

    bool initialized_ = false;
    std::unique_ptr<SaStatusListener> saStatusListener_;

    UserId activeUserId_ { INVALID_USER_ID };
    std::map<SubscribeId, ActiveUserIdCallback> subscribers_;
    std::shared_ptr<ActiveUserOsAccountSubscriber> osAccountSubscriber_;
};

DefaultActiveUserIdManager::DefaultActiveUserIdManager()
{
}

DefaultActiveUserIdManager::~DefaultActiveUserIdManager()
{
    UnsubscribeOsAccount();
}

bool DefaultActiveUserIdManager::Initialize()
{
    constexpr const char *osAccountSaName = "OsAccountService";
    {
        if (initialized_) {
            IAM_LOGI("already initialized");
            return true;
        }

        std::weak_ptr<DefaultActiveUserIdManager> weakImpl = weak_from_this();

        saStatusListener_ = SaStatusListener::Create(
            osAccountSaName, SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN,
            [weakImpl]() {
                auto impl = weakImpl.lock();
                if (impl == nullptr) {
                    IAM_LOGW("manager destroyed, ignore service ready event");
                    return;
                }
                impl->HandleOsAccountServiceReady();
            },
            [weakImpl]() {
                auto impl = weakImpl.lock();
                if (impl == nullptr) {
                    IAM_LOGW("manager destroyed, ignore service unavailable event");
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

UserId DefaultActiveUserIdManager::GetActiveUserId() const
{
    return activeUserId_;
}

std::string DefaultActiveUserIdManager::GetActiveUserName() const
{
    if (activeUserId_ == INVALID_USER_ID) {
        IAM_LOGW("active user id is invalid");
        return "";
    }

    std::string userName;
    ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountNameById(activeUserId_, userName);
    if (errCode != ERR_OK) {
        IAM_LOGE("GetOsAccountNameById failed %{public}d for %{public}d", errCode, activeUserId_);
        return "";
    }
    return userName;
}

std::unique_ptr<Subscription> DefaultActiveUserIdManager::SubscribeActiveUserId(ActiveUserIdCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);
    SubscribeId subscribeId = GetMiscManager().GetNextGlobalId();
    subscribers_[subscribeId] = std::move(callback);

    std::weak_ptr<DefaultActiveUserIdManager> weakThis = weak_from_this();
    return std::make_unique<Subscription>([weakThis, subscribeId]() {
        auto strongThis = weakThis.lock();
        if (strongThis != nullptr) {
            strongThis->UnsubscribeActiveUserId(subscribeId);
        }
    });
}

void DefaultActiveUserIdManager::UnsubscribeActiveUserId(const SubscribeId &subscribeId)
{
    subscribers_.erase(subscribeId);
}

void DefaultActiveUserIdManager::HandleOsAccountServiceReady()
{
    SubscribeOsAccount();
    SyncActiveUserId();
}

void DefaultActiveUserIdManager::HandleOsAccountServiceUnavailable()
{
    UpdateActiveUserId(INVALID_USER_ID);
    UnsubscribeOsAccount();
}

void DefaultActiveUserIdManager::OnOsAccountStateChange(const AccountSA::OsAccountStateData &data)
{
    IAM_LOGI("os account state %{public}d from %{public}d to %{public}d", static_cast<int32_t>(data.state), data.fromId,
        data.toId);

    SyncActiveUserId();
}

void DefaultActiveUserIdManager::SubscribeOsAccount()
{
    if (osAccountSubscriber_ != nullptr) {
        IAM_LOGI("already subscribed to os account");
        return;
    }

    std::set<AccountSA::OsAccountState> states = {
        AccountSA::OsAccountState::ACTIVATED,
        AccountSA::OsAccountState::UNLOCKED,
        AccountSA::OsAccountState::SWITCHED,
    };
    AccountSA::OsAccountSubscribeInfo subscribeInfo(states);
    auto subscriber = std::make_shared<ActiveUserOsAccountSubscriber>(subscribeInfo, weak_from_this());
    ENSURE_OR_RETURN(subscriber != nullptr);

    ErrCode errCode = AccountSA::OsAccountManager::SubscribeOsAccount(subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("SubscribeOsAccount failed %{public}d", errCode);
        return;
    }
    osAccountSubscriber_ = subscriber;
    IAM_LOGI("SubscribeOsAccount success");
}

void DefaultActiveUserIdManager::UnsubscribeOsAccount()
{
    if (osAccountSubscriber_ == nullptr) {
        return;
    }
    auto subscriber = osAccountSubscriber_;
    osAccountSubscriber_.reset();

    ErrCode errCode = AccountSA::OsAccountManager::UnsubscribeOsAccount(subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("UnsubscribeOsAccount failed %{public}d", errCode);
    }
}

void DefaultActiveUserIdManager::SyncActiveUserId()
{
    auto userIdOpt = QueryActiveUserIdFromSystem();
    UpdateActiveUserId(static_cast<UserId>(userIdOpt));
}

void DefaultActiveUserIdManager::UpdateActiveUserId(UserId userId)
{
    if (activeUserId_ != userId) {
        activeUserId_ = userId;
        NotifySubscribers(userId);
    }
}

void DefaultActiveUserIdManager::NotifySubscribers(UserId userId)
{
    std::vector<ActiveUserIdCallback> callbacks;
    for (const auto &entry : subscribers_) {
        callbacks.emplace_back(entry.second);
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), userId]() {
        for (const auto &callback : callbacks) {
            if (callback != nullptr) {
                callback(userId);
            }
        }
    });
}

int32_t DefaultActiveUserIdManager::QueryActiveUserIdFromSystem() const
{
    std::vector<int32_t> ids;
    ErrCode errCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (errCode != ERR_OK) {
        IAM_LOGE("QueryActiveOsAccountIds failed %{public}d", errCode);
        return INVALID_USER_ID;
    }
    if (ids.empty()) {
        IAM_LOGW("no active os account id");
        return INVALID_USER_ID;
    }

    int32_t candidate = ids.front();
    bool isVerified = false;
    errCode = AccountSA::OsAccountManager::IsOsAccountVerified(candidate, isVerified);
    if (errCode != ERR_OK) {
        IAM_LOGE("IsOsAccountVerified failed %{public}d for %{public}d", errCode, candidate);
        return INVALID_USER_ID;
    }
    if (!isVerified) {
        IAM_LOGI("active os account %{public}d not verified", candidate);
        return INVALID_USER_ID;
    }

    return candidate;
}

DefaultActiveUserIdManager::ActiveUserOsAccountSubscriber::ActiveUserOsAccountSubscriber(
    const AccountSA::OsAccountSubscribeInfo &subscribeInfo, std::weak_ptr<DefaultActiveUserIdManager> impl)
    : AccountSA::OsAccountSubscriber(subscribeInfo),
      impl_(std::move(impl))
{
}

void DefaultActiveUserIdManager::ActiveUserOsAccountSubscriber::OnStateChanged(
    const AccountSA::OsAccountStateData &data)
{
    auto impl = impl_.lock();
    if (impl == nullptr) {
        IAM_LOGW("manager has been destroyed, ignore account state change");
        return;
    }
    impl->OnOsAccountStateChange(data);
}

std::shared_ptr<IActiveUserIdManager> IActiveUserIdManager::Create()
{
    auto manager = std::make_shared<DefaultActiveUserIdManager>();
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    if (manager->Initialize() == false) {
        IAM_LOGE("failed to init fixed active user id manager");
        return nullptr;
    }
    return manager;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
