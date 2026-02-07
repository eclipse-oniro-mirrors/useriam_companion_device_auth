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

#ifndef COMPANION_DEVICE_AUTH_USER_ID_MANAGER_H
#define COMPANION_DEVICE_AUTH_USER_ID_MANAGER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "nocopyable.h"

#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using ActiveUserIdCallback = std::function<void(UserId userId)>;

class IUserIdManager : public NoCopyable {
public:
    virtual ~IUserIdManager() = default;

    static std::shared_ptr<IUserIdManager> Create();

    virtual UserId GetActiveUserId() const = 0;
    virtual std::string GetActiveUserName() const = 0;
    virtual std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) = 0;
    virtual bool IsUserIdValid(int32_t userId) = 0;

protected:
    IUserIdManager() = default;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_USER_ID_MANAGER_H
