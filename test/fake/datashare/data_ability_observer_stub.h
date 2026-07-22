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

#ifndef COMPANION_DEVICE_AUTH_FAKE_DATA_ABILITY_OBSERVER_STUB_H
#define COMPANION_DEVICE_AUTH_FAKE_DATA_ABILITY_OBSERVER_STUB_H

#include "data_ability_observer_interface.h"

namespace OHOS {
namespace AAFwk {

class DataAbilityObserverStub : public IDataAbilityObserver {
public:
    DataAbilityObserverStub() = default;
    ~DataAbilityObserverStub() override = default;

    void OnChange() override
    {
    }
};

} // namespace AAFwk
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_DATA_ABILITY_OBSERVER_STUB_H
