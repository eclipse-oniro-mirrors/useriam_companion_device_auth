/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "system_settings_manager_impl.h"

#include <new>
#include <utility>

#include "common_event_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_support.h"
#include "matching_skills.h"

#include "datashare_errno.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"

#include "adapter_manager.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "nocopyable.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SYSTEM_SETTINGS_MANAGER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr const char *SETTINGS_URI_BASE = "datashare:///com.ohos.settingsdata/entry/settingsdata/";
constexpr const char *SETTINGS_TABLE_GLOBAL = "SETTINGSDATA";
constexpr const char *SETTINGS_TABLE_SECURE = "USER_SETTINGSDATA_SECURE_";
constexpr const char *SETTINGS_DATA_EXT_URI = "datashare:///com.ohos.settingsdata.DataAbility";
constexpr const char *SETTINGS_COLUMN_KEYWORD = "KEYWORD";
constexpr const char *SETTINGS_COLUMN_VALUE = "VALUE";
constexpr SettingMeta SETTING_TABLE[] = {
    { SettingKey::DisplayDeviceName, "settings.general.display_device_name", true },
};

std::string BuildBaseUri(std::optional<int32_t> userId)
{
    if (!userId.has_value()) {
        return std::string(SETTINGS_URI_BASE) + SETTINGS_TABLE_GLOBAL + "?Proxy=true";
    }
    return std::string(SETTINGS_URI_BASE) + SETTINGS_TABLE_SECURE + std::to_string(*userId) + "?Proxy=true";
}

class DataShareHelperGuard : public NoCopyable {
public:
    DataShareHelperGuard(const wptr<IRemoteObject> &token, std::optional<int32_t> userId)
        : helper_(Create(token, userId))
    {
    }
    ~DataShareHelperGuard()
    {
        if (helper_ != nullptr) {
            helper_->Release();
        }
    }
    DataShare::DataShareHelper &operator*() const
    {
        return *helper_;
    }
    DataShare::DataShareHelper *operator->() const
    {
        return helper_.get();
    }
    explicit operator bool() const
    {
        return helper_ != nullptr;
    }

private:
    static std::shared_ptr<DataShare::DataShareHelper> Create(const wptr<IRemoteObject> &token,
        std::optional<int32_t> userId)
    {
        auto cdaService = token.promote();
        ENSURE_OR_RETURN_VAL(cdaService != nullptr, nullptr);
        std::string uriStr = BuildBaseUri(userId);
        std::string extUriStr(SETTINGS_DATA_EXT_URI);
        auto [errCode, helper] = DataShare::DataShareHelper::Create(cdaService, uriStr, extUriStr);
        if (helper == nullptr) {
            IAM_LOGE("create DataShareHelper failed, err=%{public}d, uri=%{public}s", errCode, uriStr.c_str());
        }
        return helper;
    }

    std::shared_ptr<DataShare::DataShareHelper> helper_;
};
} // namespace

std::shared_ptr<SystemSettingsManagerImpl> SystemSettingsManagerImpl::Create(const wptr<IRemoteObject> &cdaService)
{
    auto manager = std::shared_ptr<SystemSettingsManagerImpl>(new (std::nothrow) SystemSettingsManagerImpl(cdaService));
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    if (!manager->Initialize()) {
        IAM_LOGE("Initialize failed");
        return nullptr;
    }
    return manager;
}

SystemSettingsManagerImpl::SystemSettingsManagerImpl(const wptr<IRemoteObject> &cdaService) : cdaService_(cdaService)
{
}

SystemSettingsManagerImpl::~SystemSettingsManagerImpl()
{
    if (dataShareReadySubscriber_ != nullptr) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(dataShareReadySubscriber_);
    }
    cesStatusListener_.reset();
    for (auto &state : states_) {
        UnregisterOneObserver(state);
    }
    states_.clear();
}

bool SystemSettingsManagerImpl::Initialize()
{
    std::weak_ptr<SystemSettingsManagerImpl> weakSelf = shared_from_this();
    for (const auto &meta : SETTING_TABLE) {
        SettingState s;
        s.key = meta.key;
        s.dataShareKey = meta.dataShareKey;
        s.perUser = meta.perUser;
        s.userId = currentActiveUser_;
        s.observer = sptr<ObserverStub>(new (std::nothrow) ObserverStub(s.key, weakSelf));
        ENSURE_OR_RETURN_VAL(s.observer != nullptr, false);
        states_.push_back(std::move(s));
    }
    unlockedActiveUserIdSubscription_ = GetUserIdManager().SubscribeUnlockedActiveUserId([weakSelf](UserId userId) {
        TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf, userId]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnActiveUserChanged(userId >= 0 ? std::optional<int32_t>(userId) : std::nullopt);
        });
    });
    ENSURE_OR_RETURN_VAL(unlockedActiveUserIdSubscription_ != nullptr, false);
    UserId activeUserId = GetUserIdManager().GetUnlockedActiveUserId();
    OnActiveUserChanged(activeUserId >= 0 ? std::optional<int32_t>(activeUserId) : std::nullopt);

    cesStatusListener_ = SaStatusListener::Create(
        "SystemSettingsManagerCes", COMMON_EVENT_SERVICE_ID,
        [weakSelf]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnCommonEventServiceReady();
        },
        [weakSelf]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnCommonEventServiceRemoved();
        });
    if (cesStatusListener_ == nullptr) {
        IAM_LOGE("subscribe CommonEventService status failed");
    }
    return true;
}

SystemSettingsManagerImpl::SettingState *SystemSettingsManagerImpl::FindState(SettingKey key)
{
    for (auto &s : states_) {
        if (s.key == key) {
            return &s;
        }
    }
    return nullptr;
}

std::string SystemSettingsManagerImpl::GetSettingsValue(SettingKey settingKey)
{
    auto *state = FindState(settingKey);
    ENSURE_OR_RETURN_VAL(state != nullptr, "");
    return state->cachedValue;
}

std::unique_ptr<Subscription> SystemSettingsManagerImpl::SubscribeSettingsChange(SettingKey settingKey,
    SettingsChangeCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);
    auto *state = FindState(settingKey);
    ENSURE_OR_RETURN_VAL(state != nullptr, nullptr);
    uint64_t subId = GetMiscManager().GetNextGlobalId();
    state->subscribers.emplace(subId, std::move(callback));
    std::weak_ptr<SystemSettingsManagerImpl> weakSelf = shared_from_this();
    return std::make_unique<Subscription>([weakSelf, settingKey, subId]() {
        TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf, settingKey, subId]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->Unsubscribe(settingKey, subId);
        });
    });
}

void SystemSettingsManagerImpl::OnActiveUserChanged(std::optional<int32_t> newUserId)
{
    if (newUserId == currentActiveUser_) {
        return;
    }
    currentActiveUser_ = newUserId;
    for (auto &state : states_) {
        if (!state.perUser) {
            continue;
        }
        if (state.observerRegistered) {
            UnregisterOneObserver(state);
        }
        state.cachedValue.clear();
        if (newUserId.has_value()) {
            state.userId = newUserId;
        }
    }
    EnsureObservers();
    NotifyAll();
}

void SystemSettingsManagerImpl::OnCommonEventServiceReady()
{
    if (dataShareReadySubscriber_ != nullptr) {
        return;
    }
    EventFwk::MatchingSkills skills;
    skills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY);
    EventFwk::CommonEventSubscribeInfo info(skills);
    auto subscriber = std::make_shared<DataShareReadySubscriber>(info, weak_from_this());
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber)) {
        IAM_LOGE("SubscribeCommonEvent DATA_SHARE_READY failed");
        return;
    }
    dataShareReadySubscriber_ = std::move(subscriber);
    EnsureObservers();
}

void SystemSettingsManagerImpl::OnCommonEventServiceRemoved()
{
    dataShareReadySubscriber_.reset();
}

void SystemSettingsManagerImpl::OnDataShareReady()
{
    EnsureObservers();
    NotifyAll();
}

void SystemSettingsManagerImpl::EnsureObservers()
{
    for (auto &state : states_) {
        if (state.observerRegistered) {
            continue;
        }
        if (state.perUser && !currentActiveUser_.has_value()) {
            continue;
        }
        if (state.perUser) {
            state.userId = currentActiveUser_;
        }
        RegisterOneObserver(state);
    }
}

void SystemSettingsManagerImpl::RefreshCache(SettingState &state)
{
    std::string value = QueryValue(state.userId, state.dataShareKey);
    if (state.cachedValue != value) {
        IAM_LOGI("setting %{public}s changed", state.dataShareKey.c_str());
    }
    state.cachedValue = std::move(value);
}

void SystemSettingsManagerImpl::NotifySubscribers(SettingState &state)
{
    for (auto &kv : state.subscribers) {
        TaskRunnerManager::GetInstance().PostTaskOnResident([cb = kv.second]() {
            if (cb != nullptr) {
                cb();
            }
        });
    }
}

void SystemSettingsManagerImpl::NotifyAll()
{
    for (auto &state : states_) {
        NotifySubscribers(state);
    }
}

void SystemSettingsManagerImpl::OnSettingChanged(SettingKey key)
{
    auto *state = FindState(key);
    ENSURE_OR_RETURN(state != nullptr);
    RefreshCache(*state);
    NotifySubscribers(*state);
}

void SystemSettingsManagerImpl::Unsubscribe(SettingKey key, uint64_t subId)
{
    auto *state = FindState(key);
    ENSURE_OR_RETURN(state != nullptr);
    state->subscribers.erase(subId);
}

std::string SystemSettingsManagerImpl::QueryValue(std::optional<int32_t> userId, const std::string &key)
{
    DataShareHelperGuard guard(cdaService_, userId);
    if (!guard) {
        IAM_LOGE("create DataShareHelper failed, key=%{public}s", key.c_str());
        return "";
    }
    return QuerySettingsString(*guard, userId, key);
}

Uri SystemSettingsManagerImpl::BuildKeyUri(std::optional<int32_t> userId, const std::string &key) const
{
    return Uri(BuildBaseUri(userId) + "&key=" + key);
}

std::string SystemSettingsManagerImpl::QuerySettingsString(DataShare::DataShareHelper &helper,
    std::optional<int32_t> userId, const std::string &key) const
{
    std::vector<std::string> columns = { SETTINGS_COLUMN_VALUE };
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_COLUMN_KEYWORD, key);

    Uri uri = BuildKeyUri(userId, key);
    auto resultSet = helper.Query(uri, predicates, columns, nullptr);
    ENSURE_OR_RETURN_VAL(resultSet != nullptr, "");

    int32_t count = 0;
    int32_t ret = resultSet->GetRowCount(count);
    if (ret != DataShare::E_OK) {
        IAM_LOGE("GetRowCount failed %{public}d, key=%{public}s", ret, key.c_str());
        resultSet->Close();
        return "";
    }
    if (count == 0) {
        IAM_LOGE("not found value, key=%{public}s, count=%{public}d", key.c_str(), count);
        resultSet->Close();
        return "";
    }

    const int32_t index = 0;
    ret = resultSet->GoToRow(index);
    if (ret != DataShare::E_OK) {
        IAM_LOGE("GoToRow failed %{public}d, key=%{public}s", ret, key.c_str());
        resultSet->Close();
        return "";
    }
    std::string value;
    ret = resultSet->GetString(index, value);
    resultSet->Close();
    ENSURE_OR_RETURN_VAL(ret == DataShare::E_OK, "");
    return value;
}

bool SystemSettingsManagerImpl::RegisterOneObserver(SettingState &state)
{
    ENSURE_OR_RETURN_VAL(state.observer != nullptr, false);
    if (state.perUser && !state.userId.has_value()) {
        return false;
    }
    DataShareHelperGuard guard(cdaService_, state.userId);
    if (!guard) {
        return false;
    }
    Uri uri = BuildKeyUri(state.userId, state.dataShareKey);
    int32_t ret = guard->RegisterObserver(uri, state.observer);
    if (ret != DataShare::E_OK) {
        IAM_LOGE("RegisterObserver failed %{public}d key=%{public}s", ret, state.dataShareKey.c_str());
        return false;
    }
    state.observerRegistered = true;
    RefreshCache(state);
    return true;
}

void SystemSettingsManagerImpl::UnregisterOneObserver(SettingState &state)
{
    if (!state.observerRegistered || state.observer == nullptr) {
        state.observerRegistered = false;
        return;
    }
    DataShareHelperGuard guard(cdaService_, state.userId);
    if (guard) {
        Uri uri = BuildKeyUri(state.userId, state.dataShareKey);
        guard->UnregisterObserver(uri, state.observer);
    }
    state.observerRegistered = false;
}

void SystemSettingsManagerImpl::ObserverStub::OnChange()
{
    SettingKey k = key_;
    TaskRunnerManager::GetInstance().PostTaskOnResident([manager = manager_, k]() {
        auto self = manager.lock();
        if (self == nullptr) {
            IAM_LOGE("SystemSettingsManagerImpl destroyed, ignore settings change");
            return;
        }
        self->OnSettingChanged(k);
    });
}

void SystemSettingsManagerImpl::DataShareReadySubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action != EventFwk::CommonEventSupport::COMMON_EVENT_DATA_SHARE_READY) {
        return;
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident([manager = manager_]() {
        auto self = manager.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnDataShareReady();
    });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
