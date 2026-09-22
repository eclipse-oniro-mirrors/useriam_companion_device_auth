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

#include "os_account_info.h"
#include "os_account_manager.h"
#include "os_account_sub_profile_subscribe_callback.h"
#include "os_account_subprofile_client.h"
#include "os_account_subscribe_info.h"
#include "os_account_subscriber.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "sa_status_listener.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "user_id_manager.h"
#include "xcollie_helper.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_DEFAULT_USER_ID_MANAGER

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class DefaultUserIdManager final : public std::enable_shared_from_this<DefaultUserIdManager>, public IUserIdManager {
public:
    DefaultUserIdManager();
    ~DefaultUserIdManager() override;

    // User ID management
    UserId GetActiveUserId() const override;
    std::optional<std::string> GetActiveUserName() const override;
    std::string GetActiveUserTypeName() const override;
    std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) override;
    UserKey GetUnlockedActiveUserkey() const override;
    std::unique_ptr<Subscription> SubscribeUnlockedActiveUserKey(UnlockedActiveUserKeyCallback &&callback) override;
    bool IsUserIdValid(int32_t userId) override;
    std::optional<std::vector<UserKey>> GetAllValidUserKeys() const override;

    // Sub profile ID management
    int32_t GetForegroundSubProfileId(UserId userId) const override;
    bool IsForegroundSubProfileId(const UserKey &userKey) const override;
    std::optional<std::vector<int32_t>> GetOsAccountSubProfileIds(UserId userId) const override;
    std::optional<std::string> GetSubProfileName(const UserKey &userKey) const override;
    std::unique_ptr<Subscription> SubscribeSubProfileChanged(SubProfileChangedCallback &&callback) override;

private:
    class ActiveUserOsAccountSubscriber final : public AccountSA::OsAccountSubscriber {
    public:
        ActiveUserOsAccountSubscriber(const AccountSA::OsAccountSubscribeInfo &subscribeInfo,
            std::weak_ptr<DefaultUserIdManager> impl);
        ~ActiveUserOsAccountSubscriber() override = default;

        void OnStateChanged(const AccountSA::OsAccountStateData &data) override;

    private:
        std::weak_ptr<DefaultUserIdManager> impl_;
    };

    class SubProfileEventSubscriber final : public AccountSA::OsAccountSubProfileSubscribeCallback {
    public:
        explicit SubProfileEventSubscriber(std::weak_ptr<DefaultUserIdManager> impl);
        ~SubProfileEventSubscriber() override = default;

        void OnSubProfileChanged(const AccountSA::SubProfileEventData &eventData) override;

    private:
        std::weak_ptr<DefaultUserIdManager> impl_;
    };

    friend class IUserIdManager;

    bool Initialize();
    void HandleOsAccountServiceReady();
    void HandleOsAccountServiceUnavailable();
    void SubscribeOsAccount();
    void UnsubscribeOsAccount();
    void OnOsAccountStateChange(const AccountSA::OsAccountStateData &data);
    void SyncUserIds();
    void UpdateActiveUserId(UserId userId);
    void UpdateUnlockedUserId(UserId userId);
    void NotifyActiveUserIdSubscribers(UserId userId);
    void NotifyUnlockedUserIdSubscribers(const UserKey &userKey);
    void QueryActiveAndUnlockedFromSystem(UserId &active, UserId &unlocked) const;
    void UnsubscribeActiveUserId(const SubscribeId &subscribeId);
    void UnsubscribeUnlockedActiveUserKey(const SubscribeId &subscribeId);
    static std::string QueryUserTypeNameById(UserId userId);

    // Sub profile event handling
    void SubscribeSubProfileEvent();
    void UnsubscribeSubProfileEvent();
    void OnSubProfileChanged(const AccountSA::SubProfileEventData &eventData);
    void NotifySubProfileChangedSubscribers(const UserKey &userKey, SubProfileEventType eventType);
    void UnsubscribeSubProfileChanged(const SubscribeId &subscribeId);

    bool initialized_ = false;
    std::unique_ptr<SaStatusListener> saStatusListener_;

    UserId activeUserId_ { INVALID_USER_ID };
    UserId unlockedUserId_ { INVALID_USER_ID };
    int32_t foregroundSubProfileId_ { INVALID_SUB_PROFILE_ID };
    std::string activeUserTypeName_ { "normal" };
    std::map<SubscribeId, ActiveUserIdCallback> activeSubscribers_;
    std::map<SubscribeId, UnlockedActiveUserKeyCallback> unlockedSubscribers_;
    std::shared_ptr<ActiveUserOsAccountSubscriber> osAccountSubscriber_;

    std::shared_ptr<SubProfileEventSubscriber> subProfileEventSubscriber_;
    std::map<SubscribeId, SubProfileChangedCallback> subProfileChangedSubscribers_;
};

DefaultUserIdManager::DefaultUserIdManager()
{
}

DefaultUserIdManager::~DefaultUserIdManager()
{
    UnsubscribeOsAccount();
    UnsubscribeSubProfileEvent();
}

bool DefaultUserIdManager::Initialize()
{
    constexpr const char *osAccountSaName = "OsAccountService";
    {
        if (initialized_) {
            IAM_LOGI("already initialized");
            return true;
        }

        std::weak_ptr<DefaultUserIdManager> weakImpl = weak_from_this();

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

UserId DefaultUserIdManager::GetActiveUserId() const
{
    return activeUserId_;
}

std::optional<std::string> DefaultUserIdManager::GetActiveUserName() const
{
    if (activeUserId_ == INVALID_USER_ID) {
        IAM_LOGE("active user id is invalid");
        return std::nullopt;
    }

    std::string userName;
    XCollieHelper xcollie("DefaultUserIdManager-GetActiveUserName", API_CALL_TIMEOUT);
    ErrCode errCode = AccountSA::OsAccountManager::GetOsAccountNameById(activeUserId_, userName);
    if (errCode != ERR_OK) {
        IAM_LOGE("GetOsAccountNameById failed %{public}d for %{public}d", errCode, activeUserId_);
        return std::nullopt;
    }
    return userName;
}

std::string DefaultUserIdManager::GetActiveUserTypeName() const
{
    return activeUserTypeName_;
}

std::unique_ptr<Subscription> DefaultUserIdManager::SubscribeActiveUserId(ActiveUserIdCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);
    SubscribeId subscribeId = GetMiscManager().GetNextGlobalId();
    activeSubscribers_[subscribeId] = std::move(callback);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscribeId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeActiveUserId(subscribeId);
    });
}

UserKey DefaultUserIdManager::GetUnlockedActiveUserkey() const
{
    return UserKey { unlockedUserId_, foregroundSubProfileId_ };
}

std::unique_ptr<Subscription> DefaultUserIdManager::SubscribeUnlockedActiveUserKey(
    UnlockedActiveUserKeyCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);
    SubscribeId subscribeId = GetMiscManager().GetNextGlobalId();
    unlockedSubscribers_[subscribeId] = std::move(callback);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscribeId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeUnlockedActiveUserKey(subscribeId);
    });
}

void DefaultUserIdManager::UnsubscribeActiveUserId(const SubscribeId &subscribeId)
{
    activeSubscribers_.erase(subscribeId);
}

void DefaultUserIdManager::UnsubscribeUnlockedActiveUserKey(const SubscribeId &subscribeId)
{
    unlockedSubscribers_.erase(subscribeId);
}

bool DefaultUserIdManager::IsUserIdValid(int32_t userId)
{
    if (userId < 0) {
        IAM_LOGE("user id is invalid: %{public}d", userId);
        return false;
    }
    bool exists = false;
    XCollieHelper xcollie("DefaultUserIdManager-IsUserIdValid", API_CALL_TIMEOUT);
    ErrCode errCode = AccountSA::OsAccountManager::IsOsAccountExists(userId, exists);
    if (errCode != ERR_OK) {
        IAM_LOGE("IsOsAccountExists failed %{public}d for %{public}d", errCode, userId);
        return false;
    }
    return exists;
}

std::optional<std::vector<UserKey>> DefaultUserIdManager::GetAllValidUserKeys() const
{
    std::vector<AccountSA::OsAccountInfo> osAccountInfos;
    XCollieHelper xcollie("DefaultUserIdManager-GetAllValidUserKeys", API_CALL_TIMEOUT);
    ErrCode errCode = AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(osAccountInfos);
    if (errCode != ERR_OK) {
        IAM_LOGE("QueryAllCreatedOsAccounts failed %{public}d", errCode);
        return std::nullopt;
    }
    std::vector<UserKey> userIds;
    for (const auto &info : osAccountInfos) {
        UserId userId = info.GetLocalId();
        auto subProfileIds = GetOsAccountSubProfileIds(userId);
        if (!subProfileIds.has_value() || subProfileIds->empty()) {
            userIds.push_back(UserKey { userId, INVALID_SUB_PROFILE_ID });
            continue;
        }
        for (int32_t subProfileId : *subProfileIds) {
            userIds.push_back(UserKey { userId, subProfileId });
        }
    }
    return userIds;
}

int32_t DefaultUserIdManager::GetForegroundSubProfileId(UserId userId) const
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUB_PROFILES
    int32_t subProfileId = INVALID_SUB_PROFILE_ID;
    ErrCode errCode =
        AccountSA::OsAccountSubProfileClient::GetInstance().GetOsAccountForegroundSubProfileId(userId, subProfileId);
    if (errCode != ERR_OK) {
        IAM_LOGE("GetOsAccountForegroundSubProfileId failed, err:%{public}d", errCode);
        if (unlockedUserId_ == userId) {
            IAM_LOGI("GetForegroundSubProfileId success, userId:%{public}d, subProfileId:%{public}d", userId,
                subProfileId);
            return foregroundSubProfileId_;
        }
        return INVALID_SUB_PROFILE_ID;
    }
    IAM_LOGI("GetForegroundSubProfileId success, userId:%{public}d, subProfileId:%{public}d", userId, subProfileId);
    return subProfileId;
#else
    (void)userId;
    return INVALID_SUB_PROFILE_ID;
#endif
}

bool DefaultUserIdManager::IsForegroundSubProfileId(const UserKey &userKey) const
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUB_PROFILES
    if (userKey.subProfileId == INVALID_SUB_PROFILE_ID) {
        IAM_LOGE("sub profile id is invalid");
        return false;
    }
    int32_t foregroundSubProfileId = GetForegroundSubProfileId(userKey.userId);
    if (foregroundSubProfileId == INVALID_SUB_PROFILE_ID) {
        IAM_LOGE("failed to get foreground sub profile id for userId=%{public}d", userKey.userId);
        return false;
    }
    return userKey.subProfileId == foregroundSubProfileId;
#else
    (void)userKey;
    return true;
#endif
}

std::optional<std::vector<int32_t>> DefaultUserIdManager::GetOsAccountSubProfileIds(UserId userId) const
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUB_PROFILES
    std::vector<int32_t> subProfileIds;
    XCollieHelper xcollie("DefaultUserIdManager-GetOsAccountSubProfileIds", API_CALL_TIMEOUT);
    ErrCode errCode =
        AccountSA::OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfileIds(userId, subProfileIds);
    if (errCode != ERR_OK) {
        IAM_LOGE("GetOsAccountSubProfileIds failed %{public}d for userId=%{public}d", errCode, userId);
        return std::nullopt;
    }
    IAM_LOGI("GetOsAccountSubProfileIds success, userId=%{public}d, count=%{public}zu", userId, subProfileIds.size());
    return subProfileIds;
#else
    (void)userId;
    return std::vector<int32_t> { INVALID_SUB_PROFILE_ID };
#endif
}

std::optional<std::string> DefaultUserIdManager::GetSubProfileName(const UserKey &userKey) const
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUB_PROFILES
    if (userKey.subProfileId == INVALID_SUB_PROFILE_ID) {
        IAM_LOGE("sub profile id is invalid");
        return std::nullopt;
    }
    AccountSA::OsAccountSubspaceResult subspaceResult;
    AccountSA::OhosAccountInfo distributedInfo;
    ErrCode errCode = AccountSA::OsAccountSubProfileClient::GetInstance().GetOsAccountSubProfile(userKey.userId,
        userKey.subProfileId, subspaceResult, distributedInfo);
    if (errCode != ERR_OK) {
        IAM_LOGE("GetOsAccountSubProfile failed %{public}d for userId=%{public}d subProfileId=%{public}d", errCode,
            userKey.userId, userKey.subProfileId);
        return std::nullopt;
    }
    if (distributedInfo.nickname_.empty()) {
        IAM_LOGI("sub profile nickname is empty for userId=%{public}d subProfileId=%{public}d", userKey.userId,
            userKey.subProfileId);
        return std::nullopt;
    }
    return distributedInfo.nickname_;
#else
    (void)userKey;
    return std::nullopt;
#endif
}

std::unique_ptr<Subscription> DefaultUserIdManager::SubscribeSubProfileChanged(SubProfileChangedCallback &&callback)
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

void DefaultUserIdManager::UnsubscribeSubProfileChanged(const SubscribeId &subscribeId)
{
    subProfileChangedSubscribers_.erase(subscribeId);
}

void DefaultUserIdManager::HandleOsAccountServiceReady()
{
    SubscribeOsAccount();
    SubscribeSubProfileEvent();
    SyncUserIds();
}

void DefaultUserIdManager::HandleOsAccountServiceUnavailable()
{
    UpdateActiveUserId(INVALID_USER_ID);
    UpdateUnlockedUserId(INVALID_USER_ID);
    UnsubscribeOsAccount();
    UnsubscribeSubProfileEvent();
}

void DefaultUserIdManager::OnOsAccountStateChange(const AccountSA::OsAccountStateData &data)
{
    IAM_LOGI("os account state %{public}d from %{public}d to %{public}d", data.state, data.fromId, data.toId);

    SyncUserIds();
}

void DefaultUserIdManager::SubscribeOsAccount()
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

    XCollieHelper xcollie("DefaultUserIdManager-SubscribeOsAccount", API_CALL_TIMEOUT);
    ErrCode errCode = AccountSA::OsAccountManager::SubscribeOsAccount(subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("SubscribeOsAccount failed %{public}d", errCode);
        return;
    }
    osAccountSubscriber_ = subscriber;
    IAM_LOGI("SubscribeOsAccount success");
}

void DefaultUserIdManager::UnsubscribeOsAccount()
{
    if (osAccountSubscriber_ == nullptr) {
        return;
    }
    auto subscriber = osAccountSubscriber_;
    osAccountSubscriber_.reset();

    XCollieHelper xcollie("DefaultUserIdManager-UnsubscribeOsAccount", API_CALL_TIMEOUT);
    ErrCode errCode = AccountSA::OsAccountManager::UnsubscribeOsAccount(subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("UnsubscribeOsAccount failed %{public}d", errCode);
    }
}

void DefaultUserIdManager::SubscribeSubProfileEvent()
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUB_PROFILES
    if (subProfileEventSubscriber_ != nullptr) {
        IAM_LOGI("already subscribed to sub profile event");
        return;
    }

    auto subscriber = std::make_shared<SubProfileEventSubscriber>(weak_from_this());
    ENSURE_OR_RETURN(subscriber != nullptr);

    std::set<AccountSA::OsAccountSubProfileEventType> types = {
        AccountSA::OsAccountSubProfileEventType::DELETED,
        AccountSA::OsAccountSubProfileEventType::SWITCHED,
    };
    ErrCode errCode =
        AccountSA::OsAccountSubProfileClient::GetInstance().SubscribeOsAccountSubProfileEvents(types, subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("SubscribeOsAccountSubProfileEvents failed %{public}d", errCode);
        return;
    }
    subProfileEventSubscriber_ = subscriber;
    IAM_LOGI("SubscribeOsAccountSubProfileEvents success");
#endif
}

void DefaultUserIdManager::UnsubscribeSubProfileEvent()
{
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUB_PROFILES
    if (subProfileEventSubscriber_ == nullptr) {
        return;
    }
    auto subscriber = subProfileEventSubscriber_;
    subProfileEventSubscriber_.reset();

    ErrCode errCode =
        AccountSA::OsAccountSubProfileClient::GetInstance().UnsubscribeOsAccountSubProfileEvents(subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("UnsubscribeOsAccountSubProfileEvents failed %{public}d", errCode);
    }
#endif
}

void DefaultUserIdManager::OnSubProfileChanged(const AccountSA::SubProfileEventData &eventData)
{
    IAM_LOGI("sub profile changed, type=%{public}d, osAccountId=%{public}d, subProfileId=%{public}d, "
             "previousSubProfileId=%{public}d",
        static_cast<int32_t>(eventData.type_), eventData.osAccountId_, eventData.subProfileId_,
        eventData.previousSubProfileId_);

    if (eventData.type_ == AccountSA::OsAccountSubProfileEventType::DELETED) {
        NotifySubProfileChangedSubscribers(UserKey { eventData.osAccountId_, eventData.subProfileId_ },
            SubProfileEventType::DELETED);
        return;
    } else if (eventData.type_ == AccountSA::OsAccountSubProfileEventType::SWITCHED) {
        if (eventData.osAccountId_ == unlockedUserId_ && eventData.subProfileId_ == foregroundSubProfileId_) {
            IAM_LOGI("sub profile not changed, skip notification");
            return;
        }

        if (eventData.osAccountId_ == unlockedUserId_) {
            foregroundSubProfileId_ = eventData.subProfileId_;
        }
        NotifySubProfileChangedSubscribers(UserKey { eventData.osAccountId_, eventData.subProfileId_ },
            SubProfileEventType::SWITCHED);
    }
}

void DefaultUserIdManager::NotifySubProfileChangedSubscribers(const UserKey &userKey, SubProfileEventType eventType)
{
    std::vector<SubProfileChangedCallback> callbacks;
    for (const auto &entry : subProfileChangedSubscribers_) {
        callbacks.emplace_back(entry.second);
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), userKey, eventType]() {
        for (const auto &callback : callbacks) {
            if (callback != nullptr) {
                callback(userKey, eventType);
            }
        }
    });
}

void DefaultUserIdManager::SyncUserIds()
{
    UserId active = INVALID_USER_ID;
    UserId unlocked = INVALID_USER_ID;
    QueryActiveAndUnlockedFromSystem(active, unlocked);
    UpdateActiveUserId(active);
    UpdateUnlockedUserId(unlocked);
}

void DefaultUserIdManager::UpdateActiveUserId(UserId userId)
{
    if (activeUserId_ != userId) {
        IAM_LOGI("active user id %{public}d -> %{public}d", activeUserId_, userId);
        activeUserId_ = userId;
        activeUserTypeName_ = QueryUserTypeNameById(userId);
        NotifyActiveUserIdSubscribers(userId);
    }
}

void DefaultUserIdManager::UpdateUnlockedUserId(UserId userId)
{
    int32_t subProfileId = INVALID_SUB_PROFILE_ID;
    if (userId != INVALID_USER_ID) {
        subProfileId = GetForegroundSubProfileId(userId);
    }
    if (unlockedUserId_ == userId && foregroundSubProfileId_ == subProfileId) {
        return;
    }
    IAM_LOGI("unlocked user id %{public}d -> %{public}d, sub profile id %{public}d -> %{public}d", unlockedUserId_,
        userId, foregroundSubProfileId_, subProfileId);
    unlockedUserId_ = userId;
    foregroundSubProfileId_ = subProfileId;
    NotifyUnlockedUserIdSubscribers(UserKey { userId, subProfileId });
}

void DefaultUserIdManager::NotifyActiveUserIdSubscribers(UserId userId)
{
    std::vector<ActiveUserIdCallback> callbacks;
    for (const auto &entry : activeSubscribers_) {
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

void DefaultUserIdManager::NotifyUnlockedUserIdSubscribers(const UserKey &userKey)
{
    std::vector<UnlockedActiveUserKeyCallback> callbacks;
    for (const auto &entry : unlockedSubscribers_) {
        callbacks.emplace_back(entry.second);
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), userKey]() {
        for (const auto &callback : callbacks) {
            if (callback != nullptr) {
                callback(userKey);
            }
        }
    });
}

void DefaultUserIdManager::QueryActiveAndUnlockedFromSystem(UserId &active, UserId &unlocked) const
{
    active = INVALID_USER_ID;
    unlocked = INVALID_USER_ID;

    std::vector<int32_t> ids;
    XCollieHelper xcollie("DefaultUserIdManager-QueryActiveOsAccountIds", API_CALL_TIMEOUT);
    ErrCode errCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (errCode != ERR_OK) {
        IAM_LOGE("QueryActiveOsAccountIds failed %{public}d", errCode);
        return;
    }
    if (ids.empty()) {
        IAM_LOGE("no active os account id");
        return;
    }

    active = ids.front();

    bool isVerified = false;
    XCollieHelper xcollieVerify("DefaultUserIdManager-IsOsAccountVerified", API_CALL_TIMEOUT);
    errCode = AccountSA::OsAccountManager::IsOsAccountVerified(active, isVerified);
    if (errCode != ERR_OK) {
        IAM_LOGE("IsOsAccountVerified failed %{public}d for %{public}d", errCode, active);
        return;
    }
    if (!isVerified) {
        IAM_LOGI("active os account %{public}d not verified", active);
        return;
    }
    unlocked = active;
    IAM_LOGI("active user id: %{public}d (verified)", active);
}

std::string DefaultUserIdManager::QueryUserTypeNameById(UserId userId)
{
    if (userId == INVALID_USER_ID) {
        return "unknown";
    }

    AccountSA::OsAccountInfo info;
    XCollieHelper xcollie("DefaultUserIdManager-QueryUserTypeNameById", API_CALL_TIMEOUT);
    ErrCode errCode = AccountSA::OsAccountManager::QueryOsAccountById(userId, info);
    if (errCode != ERR_OK) {
        IAM_LOGE("QueryOsAccountById failed %{public}d for %{public}d", errCode, userId);
        return "unknown";
    }

    switch (info.GetType()) {
        case AccountSA::ADMIN:
            return "admin";
        case AccountSA::NORMAL:
            return "normal";
        case AccountSA::GUEST:
            return "guest";
        case AccountSA::MAINTENANCE:
            return "maintenance";
        case AccountSA::PRIVATE:
            return "private";
        default:
            return "unknown";
    }
}

DefaultUserIdManager::ActiveUserOsAccountSubscriber::ActiveUserOsAccountSubscriber(
    const AccountSA::OsAccountSubscribeInfo &subscribeInfo, std::weak_ptr<DefaultUserIdManager> impl)
    : AccountSA::OsAccountSubscriber(subscribeInfo),
      impl_(std::move(impl))
{
}

void DefaultUserIdManager::ActiveUserOsAccountSubscriber::OnStateChanged(const AccountSA::OsAccountStateData &data)
{
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakImpl = impl_, data]() {
        auto impl = weakImpl.lock();
        if (impl == nullptr) {
            IAM_LOGE("manager has been destroyed, ignore account state change");
            return;
        }
        impl->OnOsAccountStateChange(data);
    });
}

DefaultUserIdManager::SubProfileEventSubscriber::SubProfileEventSubscriber(std::weak_ptr<DefaultUserIdManager> impl)
    : impl_(std::move(impl))
{
}

void DefaultUserIdManager::SubProfileEventSubscriber::OnSubProfileChanged(
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
std::shared_ptr<IUserIdManager> IUserIdManager::Create()
{
    auto manager = std::make_shared<DefaultUserIdManager>();
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    if (manager->Initialize() == false) {
        IAM_LOGE("failed to init default user id manager");
        return nullptr;
    }
    return manager;
}
#endif // ENABLE_TEST

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
