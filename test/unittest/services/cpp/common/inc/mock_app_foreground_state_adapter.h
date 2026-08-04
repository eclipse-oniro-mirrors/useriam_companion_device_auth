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

#ifndef COMPANION_DEVICE_AUTH_MOCK_APP_FOREGROUND_STATE_ADAPTER_H
#define COMPANION_DEVICE_AUTH_MOCK_APP_FOREGROUND_STATE_ADAPTER_H

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "app_foreground_state_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockAppForegroundStateAdapter : public IAppForegroundStateAdapter {
public:
    MOCK_METHOD(std::unique_ptr<Subscription>, AddWatchedApp, (const std::string &bundleName), (override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeForegroundWatchedApps,
        (const ForegroundWatchedAppsHandler &handler), (override));
    MOCK_METHOD(std::vector<std::string>, GetForegroundWatchedApps, (), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MOCK_APP_FOREGROUND_STATE_ADAPTER_H
