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

#ifndef COMPANION_DEVICE_AUTH_SYSTEM_SETTINGS_MANAGER_H
#define COMPANION_DEVICE_AUTH_SYSTEM_SETTINGS_MANAGER_H

#include <functional>
#include <memory>
#include <string>

#include "nocopyable.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SettingsChangeCallback = std::function<void(void)>;

enum class SettingKey : uint32_t {
    DisplayDeviceName,
};

class ISystemSettingsManager : public NoCopyable {
public:
    virtual ~ISystemSettingsManager() = default;

    virtual std::string GetSettingsValue(SettingKey settingKey) = 0;
    virtual std::unique_ptr<Subscription> SubscribeSettingsChange(SettingKey settingKey,
        SettingsChangeCallback &&callback) = 0;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SYSTEM_SETTINGS_MANAGER_H
