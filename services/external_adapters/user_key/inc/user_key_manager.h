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

#ifndef COMPANION_DEVICE_AUTH_USER_KEY_MANAGER_H
#define COMPANION_DEVICE_AUTH_USER_KEY_MANAGER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "nocopyable.h"

#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using ActiveUserIdCallback = std::function<void(UserId userId)>;

enum class UserKeyEventType : int32_t {
    USER_KEY_UPDATE = 1,
    USER_KEY_DELETED = 2,
};

using UnlockedActiveUserKeyCallback = std::function<void(const UserKey &userKey, UserKeyEventType eventType)>;

class IUserKeyManager : public NoCopyable {
public:
    virtual ~IUserKeyManager() = default;

    static std::shared_ptr<IUserKeyManager> Create();

    // User ID management
    virtual std::optional<std::string> GetActiveUserName() const = 0;
    virtual std::string GetActiveUserTypeName() const = 0;
    virtual UserId GetActiveUserId() const = 0;
    virtual std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) = 0;
    virtual UserKey GetUnlockedActiveUserkey() const = 0;
    virtual std::unique_ptr<Subscription> SubscribeUnlockedActiveUserKey(UnlockedActiveUserKeyCallback &&callback) = 0;
    virtual bool IsUserIdValid(int32_t userId) = 0;
    virtual std::optional<std::vector<UserKey>> GetAllValidUserKeys() const = 0;

    // Sub profile ID management
    virtual int32_t GetForegroundSubProfileId(UserId userId) const = 0;
    virtual std::optional<std::string> GetSubProfileName(const UserKey &userKey) const = 0;

protected:
    IUserKeyManager() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_USER_KEY_MANAGER_H
