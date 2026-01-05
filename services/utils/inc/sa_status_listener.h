/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_SA_STATUS_LISTENER_H
#define COMPANION_DEVICE_AUTH_SA_STATUS_LISTENER_H

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "nocopyable.h"
#include "refbase.h"
#include "system_ability_status_change_stub.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SaStatusListener : public NoCopyable {
public:
    using AddFunc = std::function<void(void)>;
    using RemoveFunc = std::function<void(void)>;

    static std::unique_ptr<SaStatusListener> Create(const std::string &name, int32_t systemAbilityId, AddFunc &&addFunc,
        RemoveFunc &&removeFunc);

    ~SaStatusListener();

#ifndef ENABLE_TEST
private:
#endif
    class SaStatusStub;

    SaStatusListener(const std::string &name, int32_t systemAbilityId, AddFunc &&addFunc, RemoveFunc &&removeFunc);

    bool Subscribe();
    void Unsubscribe();

    int32_t systemAbilityId_ = -1;
    sptr<SystemAbilityStatusChangeStub> stub_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SA_STATUS_LISTENER_H
