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

#ifndef FAKE_SYSTEM_ABILITY_LISTENER_H
#define FAKE_SYSTEM_ABILITY_LISTENER_H

#include <functional>
#include <string>

#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SystemAbilityListener : public SystemAbilityStatusChangeStub {
public:
    using AddFunc = std::function<void(void)>;
    using RemoveFunc = std::function<void(void)>;

    SystemAbilityListener(std::string name, int32_t systemAbilityId, AddFunc addFunc, RemoveFunc removeFunc)
        : name_(name),
          systemAbilityId_(systemAbilityId),
          addFunc_(addFunc),
          removeFunc_(removeFunc)
    {
    }

    ~SystemAbilityListener() override = default;

    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
        if (addFunc_) {
            addFunc_();
        }
    }

    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override
    {
        if (removeFunc_) {
            removeFunc_();
        }
    }

    // Static methods for SA monitoring (fake implementations for unit tests)
    static int32_t Subscribe(int32_t systemAbilityId, const sptr<SystemAbilityListener> &listener)
    {
        (void)systemAbilityId;
        (void)listener;
        return 0; // Return success for unit tests
    }

    static int32_t UnSubscribe(int32_t systemAbilityId, sptr<SystemAbilityListener> &listener)
    {
        (void)systemAbilityId;
        (void)listener;
        return 0; // Return success for unit tests
    }

private:
    std::string name_;
    int32_t systemAbilityId_;
    AddFunc addFunc_;
    RemoveFunc removeFunc_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // FAKE_SYSTEM_ABILITY_LISTENER_H
