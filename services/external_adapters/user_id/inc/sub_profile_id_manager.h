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

#ifndef COMPANION_DEVICE_AUTH_SUB_PROFILE_ID_MANAGER_H
#define COMPANION_DEVICE_AUTH_SUB_PROFILE_ID_MANAGER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "nocopyable.h"

#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

enum class SubProfileEventType : int32_t {
    DELETED = 1,
    SWITCHED = 3,
};

using SubProfileChangedCallback =
    std::function<void(UserId userId, int32_t subProfileId, SubProfileEventType eventType)>;

class ISubProfileIdManager : public NoCopyable {
public:
    virtual ~ISubProfileIdManager() = default;

    static std::shared_ptr<ISubProfileIdManager> Create();

    virtual int32_t GetForegroundSubProfileId(UserId userId) const = 0;
    virtual bool IsForegroundSubProfileId(UserId userId, int32_t subProfileId) const = 0;
    virtual std::optional<std::string> GetSubProfileName(UserId userId, int32_t subProfileId) const = 0;
    virtual std::unique_ptr<Subscription> SubscribeSubProfileChanged(SubProfileChangedCallback &&callback) = 0;

protected:
    ISubProfileIdManager() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SUB_PROFILE_ID_MANAGER_H
