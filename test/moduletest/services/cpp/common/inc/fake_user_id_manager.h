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

#ifndef COMPANION_DEVICE_AUTH_FAKE_USER_ID_MANAGER_H
#define COMPANION_DEVICE_AUTH_FAKE_USER_ID_MANAGER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "subscription.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeUserIdManager : public IUserIdManager {
public:
    FakeUserIdManager() = default;
    ~FakeUserIdManager() override = default;

    UserId GetActiveUserId() const override
    {
        return userId_;
    }
    std::optional<std::string> GetActiveUserName() const override
    {
        return userName_;
    }
    std::string GetActiveUserTypeName() const override
    {
        return userTypeName_;
    }

    std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) override
    {
        callbacks_.push_back(std::move(callback));
        return std::make_unique<Subscription>([this]() { callbacks_.clear(); });
    }

    bool IsUserIdValid(int32_t userId) override
    {
        return userId > 0;
    }

    // Test backdoor: set user and auto-notify all subscribers
    void TestSetActiveUser(UserId userId, const std::string &userName = "", const std::string &userTypeName = "normal")
    {
        userId_ = userId;
        userName_ = userName;
        userTypeName_ = userTypeName;
        for (auto &cb : callbacks_) {
            cb(userId);
        }
    }

private:
    UserId userId_ = 0;
    std::string userName_;
    std::string userTypeName_ { "normal" };
    std::vector<ActiveUserIdCallback> callbacks_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_USER_ID_MANAGER_H
