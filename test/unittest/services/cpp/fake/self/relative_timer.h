/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_RELATIVE_TIMER_H
#define COMPANION_DEVICE_AUTH_RELATIVE_TIMER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "singleton.h"
#include "subscription.h"
#include "timer.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class RelativeTimer final : public Singleton<RelativeTimer> {
public:
    using TimerCallback = std::function<void()>;
    RelativeTimer();
    ~RelativeTimer() override;
    std::unique_ptr<Subscription> Register(TimerCallback &&callback, uint32_t ms);
    std::unique_ptr<Subscription> RegisterPeriodic(TimerCallback &&callback, uint32_t ms);
    void PostTask(TimerCallback &&callback, uint32_t ms);

#ifdef ENABLE_TEST
    void ExecuteAll();
#endif
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_RELATIVE_TIMER_H
