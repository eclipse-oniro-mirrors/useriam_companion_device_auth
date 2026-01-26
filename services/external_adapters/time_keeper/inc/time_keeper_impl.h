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

#ifndef COMPANION_DEVICE_AUTH_TIME_KEEPER_IMPL_H
#define COMPANION_DEVICE_AUTH_TIME_KEEPER_IMPL_H

#include <memory>
#include <optional>

#include "time_keeper.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class TimeKeeperImpl final : public std::enable_shared_from_this<TimeKeeperImpl>, public ITimeKeeper {
public:
    static std::shared_ptr<TimeKeeperImpl> Create();

    ~TimeKeeperImpl() override = default;

    std::optional<SystemTimeMs> GetSystemTimeMs() override;
    std::optional<SteadyTimeMs> GetSteadyTimeMs() override;

private:
    TimeKeeperImpl() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TIME_KEEPER_IMPL_H
