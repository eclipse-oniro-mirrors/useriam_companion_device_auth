/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "relative_timer.h"

#include <algorithm>
#include <utility>

#include "iam_logger.h"

#include "subscription.h"
#include "timer.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

#define LOG_TAG "COMPANION_DEVICE_AUTH"

RelativeTimer::RelativeTimer() : timer_("companion_device_auth_relative_timer")
{
    timer_.Setup();
    IAM_LOGI("relative timer setup");
}

RelativeTimer::~RelativeTimer()
{
    timer_.Shutdown();
    IAM_LOGI("relative timer shutdown");
}

std::unique_ptr<Subscription> RelativeTimer::Register(TimerCallback &&callback, uint32_t ms)
{
    uint32_t timerId = timer_.Register(std::move(callback), ms, true);
    return std::make_unique<Subscription>([this, timerId]() { timer_.Unregister(timerId); });
}

std::unique_ptr<Subscription> RelativeTimer::RegisterPeriodic(TimerCallback &&callback, uint32_t ms)
{
    uint32_t timerId = timer_.Register(std::move(callback), ms, false);
    return std::make_unique<Subscription>([this, timerId]() { timer_.Unregister(timerId); });
}

void RelativeTimer::PostTask(TimerCallback &&callback, uint32_t ms)
{
    (void)timer_.Register(std::move(callback), ms, true);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
