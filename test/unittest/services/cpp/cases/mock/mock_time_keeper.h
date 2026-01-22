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

#ifndef COMPANION_DEVICE_AUTH_MOCK_TIME_KEEPER_H
#define COMPANION_DEVICE_AUTH_MOCK_TIME_KEEPER_H

#include <optional>

#include "service_common.h"
#include "time_keeper.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockTimeKeeper : public ITimeKeeper {
public:
    MockTimeKeeper() : systemTimeMs_(0), steadyTimeMs_(0)
    {
    }

    void SetSystemTime(SystemTimeMs timeMs)
    {
        systemTimeMs_ = timeMs;
    }

    void SetSteadyTime(SteadyTimeMs timeMs)
    {
        steadyTimeMs_ = timeMs;
    }

    void AdvanceSystemTime(SteadyTimeMs deltaMs)
    {
        systemTimeMs_ += deltaMs;
    }

    void AdvanceSteadyTime(SteadyTimeMs deltaMs)
    {
        steadyTimeMs_ += deltaMs;
    }

    std::optional<SystemTimeMs> GetSystemTimeMs() override
    {
        return systemTimeMs_;
    }

    std::optional<SteadyTimeMs> GetSteadyTimeMs() override
    {
        return steadyTimeMs_;
    }

private:
    SystemTimeMs systemTimeMs_;
    SteadyTimeMs steadyTimeMs_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MOCK_TIME_KEEPER_H
