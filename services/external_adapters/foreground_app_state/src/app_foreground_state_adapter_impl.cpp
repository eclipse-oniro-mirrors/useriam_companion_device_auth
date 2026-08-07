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

#include "app_foreground_state_adapter_impl.h"

#include <memory>
#include <new>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "app_mgr_constants.h"
#include "app_mgr_interface.h"
#include "app_state_data.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "sa_status_listener.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "subscription.h"
#include "task_runner_manager.h"
#include "xcollie_helper.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_APP_FOREGROUND_STATE_ADAPTER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using namespace OHOS::AppExecFwk;

class AppForegroundStateObserver : public ApplicationStateObserverStub {
public:
    explicit AppForegroundStateObserver(std::weak_ptr<AppForegroundStateAdapterImpl> weak) : weak_(std::move(weak))
    {
    }
    ~AppForegroundStateObserver() override = default;

    void OnAppStateChanged(const AppStateData &appStateData) override
    {
        const auto &bundleName = appStateData.bundleName;
        if (bundleName.empty()) {
            return;
        }
        bool foreground = static_cast<ApplicationState>(appStateData.state) == ApplicationState::APP_STATE_FOREGROUND;
        IAM_LOGI("OnAppStateChanged bundleName:%{public}s foreground:%{public}d", bundleName.c_str(), foreground);
        TaskRunnerManager::GetInstance().PostTaskOnResident(
            [weak = weak_, bundleName = std::string(bundleName), foreground]() {
                if (auto self = weak.lock()) {
                    self->HandleAppStateChanged(bundleName, foreground);
                }
            });
    }

private:
    std::weak_ptr<AppForegroundStateAdapterImpl> weak_;
};

AppForegroundStateAdapterImpl::~AppForegroundStateAdapterImpl()
{
    UnregisterObserver();
}

std::shared_ptr<AppForegroundStateAdapterImpl> AppForegroundStateAdapterImpl::Create()
{
    auto adapter = std::shared_ptr<AppForegroundStateAdapterImpl>(new (std::nothrow) AppForegroundStateAdapterImpl());
    ENSURE_OR_RETURN_VAL(adapter != nullptr, nullptr);
    if (!adapter->Init()) {
        IAM_LOGE("AppForegroundStateAdapterImpl init failed");
        return nullptr;
    }
    return adapter;
}

bool AppForegroundStateAdapterImpl::Init()
{
    std::weak_ptr<AppForegroundStateAdapterImpl> weakSelf = weak_from_this();
    saStatusListener_ = SaStatusListener::Create(
        "AppMgrService", APP_MGR_SERVICE_ID,
        [weakSelf]() {
            if (auto self = weakSelf.lock()) {
                self->OnSystemAbilityAdd();
            }
        },
        [weakSelf]() {
            if (auto self = weakSelf.lock()) {
                self->OnSystemAbilityRemove();
            }
        });
    if (saStatusListener_ == nullptr) {
        IAM_LOGE("SubscribeSystemAbility failed for appmgr SA %{public}d", APP_MGR_SERVICE_ID);
        return false;
    }
    return true;
}

std::unique_ptr<Subscription> AppForegroundStateAdapterImpl::AddWatchedApp(const std::string &bundleName)
{
    SubscribeId id = GetMiscManager().GetNextGlobalId();
    watchedBundles_[id] = bundleName;
    RefreshObserver();
    return std::make_unique<Subscription>([weak = weak_from_this(), id]() {
        if (auto self = weak.lock()) {
            self->RemoveWatchedApp(id);
        }
    });
}

void AppForegroundStateAdapterImpl::RemoveWatchedApp(SubscribeId id)
{
    watchedBundles_.erase(id);
    TaskRunnerManager::GetInstance().PostTaskOnResident([weak = weak_from_this()]() {
        if (auto self = weak.lock()) {
            self->RefreshObserver();
        }
    });
}

std::unique_ptr<Subscription> AppForegroundStateAdapterImpl::SubscribeForegroundWatchedApps(
    const ForegroundWatchedAppsHandler &handler)
{
    SubscribeId id = GetMiscManager().GetNextGlobalId();
    foregroundHandlers_[id] = handler;
    NotifyOneSubscriber(id);
    return std::make_unique<Subscription>([weak = weak_from_this(), id]() {
        if (auto self = weak.lock()) {
            self->UnsubscribeForegroundApps(id);
        }
    });
}

void AppForegroundStateAdapterImpl::UnsubscribeForegroundApps(SubscribeId id)
{
    foregroundHandlers_.erase(id);
}

std::vector<std::string> AppForegroundStateAdapterImpl::GetForegroundWatchedApps()
{
    auto watched = GetWatchedBundles();
    std::vector<std::string> result;
    for (const auto &bundleName : watched) {
        if (foregroundBundles_.count(bundleName) > 0) {
            result.push_back(bundleName);
        }
    }
    return result;
}

void AppForegroundStateAdapterImpl::RefreshObserver()
{
    std::set<std::string> desired = GetWatchedBundles();
    if (desired == registeredBundles_ && observer_ != nullptr) {
        return;
    }
    if (observer_ != nullptr) {
        UnregisterObserver();
    }
    if (!desired.empty()) {
        RegisterObserver();
    }
}

bool AppForegroundStateAdapterImpl::RegisterObserver()
{
    if (observer_ != nullptr) {
        return true;
    }
    auto observer = sptr<AppForegroundStateObserver>(new (std::nothrow) AppForegroundStateObserver(weak_from_this()));
    ENSURE_OR_RETURN_VAL(observer != nullptr, false);
    auto appMgr = GetIAppMgr();
    ENSURE_OR_RETURN_VAL(appMgr != nullptr, false);
    XCollieHelper xcollie("AppForegroundStateAdapter-Subscribe", API_CALL_TIMEOUT);
    std::set<std::string> bundles = GetWatchedBundles();
    int32_t ret = appMgr->RegisterApplicationStateObserver(observer, { bundles.begin(), bundles.end() });
    if (ret != 0) {
        IAM_LOGE("RegisterApplicationStateObserver with %{public}zu bundles failed ret=%{public}d", bundles.size(),
            ret);
        return false;
    }
    observer_ = observer;
    registeredBundles_ = std::move(bundles);
    RefreshForegroundCache();
    NotifySubscribers();
    return true;
}

void AppForegroundStateAdapterImpl::UnregisterObserver()
{
    if (observer_ == nullptr) {
        return;
    }
    auto appMgr = GetIAppMgr();
    ENSURE_OR_RETURN_DESC("GetIAppMgr failed, keep observer registered", appMgr != nullptr);
    auto observer = observer_;
    observer_ = nullptr;
    registeredBundles_.clear();
    XCollieHelper xcollie("AppForegroundStateAdapter-Unsubscribe", API_CALL_TIMEOUT);
    int32_t ret = appMgr->UnregisterApplicationStateObserver(observer);
    if (ret != 0) {
        IAM_LOGE("UnregisterApplicationStateObserver failed ret=%{public}d", ret);
    }
}

void AppForegroundStateAdapterImpl::OnSystemAbilityAdd()
{
    IAM_LOGI("appmgr SA %{public}d online, re-register observer", APP_MGR_SERVICE_ID);
    UnregisterObserver();
    if (!GetWatchedBundles().empty()) {
        RegisterObserver();
    }
}

void AppForegroundStateAdapterImpl::OnSystemAbilityRemove()
{
    IAM_LOGI("appmgr SA %{public}d offline, hold last-known foreground state", APP_MGR_SERVICE_ID);
}

sptr<OHOS::AppExecFwk::IAppMgr> AppForegroundStateAdapterImpl::GetIAppMgr()
{
    auto sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ENSURE_OR_RETURN_VAL(sam != nullptr, nullptr);
    sptr<IRemoteObject> remote = sam->GetSystemAbility(APP_MGR_SERVICE_ID);
    ENSURE_OR_RETURN_VAL(remote != nullptr, nullptr);
    return iface_cast<OHOS::AppExecFwk::IAppMgr>(remote);
}

void AppForegroundStateAdapterImpl::RefreshForegroundCache()
{
    auto appMgr = GetIAppMgr();
    ENSURE_OR_RETURN(appMgr != nullptr);
    std::vector<AppStateData> list;
    XCollieHelper xcollie("AppForegroundStateAdapter-GetForeground", API_CALL_TIMEOUT);
    if (appMgr->GetForegroundApplications(list) != 0) {
        IAM_LOGE("GetForegroundApplications failed");
        return;
    }
    auto watched = GetWatchedBundles();
    std::set<std::string> foregroundBundles;
    for (const auto &item : list) {
        if (!item.bundleName.empty() && watched.count(item.bundleName) > 0) {
            foregroundBundles.insert(item.bundleName);
        }
    }
    foregroundBundles_ = std::move(foregroundBundles);
}

std::set<std::string> AppForegroundStateAdapterImpl::GetWatchedBundles() const
{
    std::set<std::string> bundles;
    for (const auto &item : watchedBundles_) {
        if (!item.second.empty()) {
            bundles.insert(item.second);
        }
    }
    return bundles;
}

void AppForegroundStateAdapterImpl::HandleAppStateChanged(const std::string &bundleName, bool foreground)
{
    bool isWatched = false;
    for (const auto &item : watchedBundles_) {
        if (item.second == bundleName) {
            isWatched = true;
            break;
        }
    }
    if (!isWatched) {
        return;
    }
    if (foreground) {
        foregroundBundles_.insert(bundleName);
    } else {
        foregroundBundles_.erase(bundleName);
    }
    NotifySubscribers();
}

void AppForegroundStateAdapterImpl::NotifyOneSubscriber(SubscribeId id)
{
    auto it = foregroundHandlers_.find(id);
    if (it == foregroundHandlers_.end() || !it->second) {
        return;
    }
    auto handler = it->second;
    auto foregroundApps = GetForegroundWatchedApps();
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [handler = std::move(handler), foregroundApps = std::move(foregroundApps)]() {
            handler(foregroundApps);
        });
}

void AppForegroundStateAdapterImpl::NotifySubscribers()
{
    auto foregroundApps = GetForegroundWatchedApps();
    std::vector<ForegroundWatchedAppsHandler> snapshot;
    snapshot.reserve(foregroundHandlers_.size());
    for (const auto &item : foregroundHandlers_) {
        if (item.second) {
            snapshot.push_back(item.second);
        }
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [snapshot = std::move(snapshot), foregroundApps = std::move(foregroundApps)]() {
            for (const auto &handler : snapshot) {
                handler(foregroundApps);
            }
        });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
