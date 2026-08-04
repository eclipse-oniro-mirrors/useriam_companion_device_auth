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

#ifndef COMPANION_DEVICE_AUTH_APP_FOREGROUND_STATE_ADAPTER_IMPL_H
#define COMPANION_DEVICE_AUTH_APP_FOREGROUND_STATE_ADAPTER_IMPL_H

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "app_foreground_state_adapter.h"
#include "app_mgr_interface.h"
#include "application_state_observer_stub.h"
#include "refbase.h"
#include "sa_status_listener.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class AppForegroundStateAdapterImpl : public IAppForegroundStateAdapter,
                                      public std::enable_shared_from_this<AppForegroundStateAdapterImpl> {
public:
    static std::shared_ptr<AppForegroundStateAdapterImpl> Create();
    ~AppForegroundStateAdapterImpl() override;

    std::unique_ptr<Subscription> AddWatchedApp(const std::string &bundleName) override;
    std::unique_ptr<Subscription> SubscribeForegroundWatchedApps(const ForegroundWatchedAppsHandler &handler) override;
    std::vector<std::string> GetForegroundWatchedApps() override;

private:
    AppForegroundStateAdapterImpl() = default;
    friend class AppForegroundStateObserver;

    bool Init();

    void RemoveWatchedApp(SubscribeId id);
    void UnsubscribeForegroundApps(SubscribeId id);

    void RefreshObserver();
    bool RegisterObserver();
    void UnregisterObserver();

    sptr<OHOS::AppExecFwk::IAppMgr> GetIAppMgr();
    void RefreshForegroundCache();
    std::set<std::string> GetWatchedBundles() const;
    void HandleAppStateChanged(const std::string &bundleName, bool foreground);
    void NotifyOneSubscriber(SubscribeId id);
    void NotifySubscribers();

    void OnSystemAbilityAdd();
    void OnSystemAbilityRemove();

    std::unordered_map<SubscribeId, std::string> watchedBundles_;
    std::map<SubscribeId, ForegroundWatchedAppsHandler> foregroundHandlers_;
    std::set<std::string> foregroundBundles_;
    sptr<OHOS::AppExecFwk::ApplicationStateObserverStub> observer_;
    std::set<std::string> registeredBundles_;
    std::unique_ptr<SaStatusListener> saStatusListener_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_APP_FOREGROUND_STATE_ADAPTER_IMPL_H
