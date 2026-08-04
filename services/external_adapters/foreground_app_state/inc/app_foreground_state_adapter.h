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

#ifndef COMPANION_DEVICE_AUTH_APP_FOREGROUND_STATE_ADAPTER_H
#define COMPANION_DEVICE_AUTH_APP_FOREGROUND_STATE_ADAPTER_H

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "nocopyable.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using ForegroundWatchedAppsHandler = std::function<void(const std::vector<std::string> &bundleNames)>;

class IAppForegroundStateAdapter : public NoCopyable {
public:
    virtual ~IAppForegroundStateAdapter() = default;

    virtual std::unique_ptr<Subscription> AddWatchedApp(const std::string &bundleName) = 0;
    virtual std::unique_ptr<Subscription> SubscribeForegroundWatchedApps(
        const ForegroundWatchedAppsHandler &handler) = 0;
    virtual std::vector<std::string> GetForegroundWatchedApps() = 0;

protected:
    IAppForegroundStateAdapter() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_APP_FOREGROUND_STATE_ADAPTER_H
