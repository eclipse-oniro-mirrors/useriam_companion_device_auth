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

#ifndef COMPANION_DEVICE_AUTH_FAKE_APP_FOREGROUND_STATE_ADAPTER_H
#define COMPANION_DEVICE_AUTH_FAKE_APP_FOREGROUND_STATE_ADAPTER_H

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "app_foreground_state_adapter.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Default bundle name used by module tests to represent a foreground subscriber.
inline constexpr const char *FOREGROUND_TEST_BUNDLE = "test.foreground.app";

class FakeAppForegroundStateAdapter : public IAppForegroundStateAdapter,
                                      public std::enable_shared_from_this<FakeAppForegroundStateAdapter> {
public:
    FakeAppForegroundStateAdapter() = default;
    ~FakeAppForegroundStateAdapter() override = default;

    std::unique_ptr<Subscription> AddWatchedApp(const std::string &bundleName) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SubscribeId id = nextBundleId_++;
        watchedBundles_[id] = bundleName;
        return std::make_unique<Subscription>([self = shared_from_this(), id]() { self->UnsubscribeBundle(id); });
    }

    std::unique_ptr<Subscription> SubscribeForegroundWatchedApps(const ForegroundWatchedAppsHandler &handler) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        SubscribeId id = nextHandlerId_++;
        handlers_[id] = handler;
        return std::make_unique<Subscription>([self = shared_from_this(), id]() { self->ReleaseHandler(id); });
    }

    std::vector<std::string> GetForegroundWatchedApps() override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return GetForegroundWatchedAppsLocked();
    }

    // Test backdoor: set the snapshot returned by GetForegroundWatchedApps.
    void TestSetForegroundBundles(std::set<std::string> bundles)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        foreground_ = std::move(bundles);
    }

    // Test backdoor: deliver an app foreground change to every live subscriber and update the
    // foreground set, mirroring how the real adapter forwards OnAppStateChanged.
    void TestSimulateStateChanged(const std::string &bundleName, bool foreground)
    {
        std::vector<ForegroundWatchedAppsHandler> snapshot;
        std::vector<std::string> foregroundApps;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (foreground) {
                foreground_.insert(bundleName);
            } else {
                foreground_.erase(bundleName);
            }
            foregroundApps = GetForegroundWatchedAppsLocked();
            snapshot.reserve(handlers_.size());
            for (const auto &item : handlers_) {
                if (item.second) {
                    snapshot.push_back(item.second);
                }
            }
        }
        for (const auto &handler : snapshot) {
            handler(foregroundApps);
        }
    }

private:
    std::vector<std::string> GetForegroundWatchedAppsLocked()
    {
        std::set<std::string> watched;
        for (const auto &item : watchedBundles_) {
            watched.insert(item.second);
        }
        std::vector<std::string> result;
        for (const auto &bundleName : watched) {
            if (foreground_.count(bundleName) > 0) {
                result.push_back(bundleName);
            }
        }
        return result;
    }

    void UnsubscribeBundle(SubscribeId id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        watchedBundles_.erase(id);
    }

    void ReleaseHandler(SubscribeId id)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        handlers_.erase(id);
    }

    std::mutex mutex_;
    SubscribeId nextBundleId_ { 0 };
    std::unordered_map<SubscribeId, std::string> watchedBundles_;
    SubscribeId nextHandlerId_ { 0 };
    std::map<SubscribeId, ForegroundWatchedAppsHandler> handlers_;
    std::set<std::string> foreground_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_APP_FOREGROUND_STATE_ADAPTER_H
