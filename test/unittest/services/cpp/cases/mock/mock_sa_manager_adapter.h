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

#ifndef MOCK_SA_MANAGER_ADAPTER_H
#define MOCK_SA_MANAGER_ADAPTER_H

#include "refbase.h"
#include "system_ability_status_change_stub.h"
#include <gmock/gmock.h>

#include "sa_manager_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockSAManagerAdapter : public ISaManagerAdapter {
public:
    MOCK_METHOD(bool, SubscribeSystemAbility,
        (int32_t systemAbilityId, const sptr<SystemAbilityStatusChangeStub> &listener), (override));
    MOCK_METHOD(bool, UnSubscribeSystemAbility,
        (int32_t systemAbilityId, const sptr<SystemAbilityStatusChangeStub> &listener), (override));
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // MOCK_SA_MANAGER_ADAPTER_H
