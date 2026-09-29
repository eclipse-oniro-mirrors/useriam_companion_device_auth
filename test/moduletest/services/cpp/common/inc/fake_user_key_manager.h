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

#ifndef COMPANION_DEVICE_AUTH_FAKE_USER_KEY_MANAGER_H
#define COMPANION_DEVICE_AUTH_FAKE_USER_KEY_MANAGER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "subscription.h"
#include "user_key_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeUserKeyManager : public IUserKeyManager {
public:
    FakeUserKeyManager() = default;
    ~FakeUserKeyManager() override = default;

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

    UserKey GetUnlockedActiveUserkey() const override
    {
        return UserKey { GetActiveUserId(), INVALID_SUB_PROFILE_ID };
    }

    std::unique_ptr<Subscription> SubscribeUnlockedActiveUserKey(UnlockedActiveUserKeyCallback &&callback) override
    {
        activeUserKeyChangeCallbacks_.push_back(std::move(callback));
        return std::make_unique<Subscription>([this]() { activeUserKeyChangeCallbacks_.clear(); });
    }

    bool IsUserIdValid(int32_t userId) override
    {
        return userId > 0;
    }

    std::optional<std::vector<UserKey>> GetAllValidUserKeys() const override
    {
        return std::vector<UserKey> { { userId_, INVALID_SUB_PROFILE_ID } };
    }

    // Sub profile ID management
    // The production ConstantSubProfileIdManager always returns INVALID_SUB_PROFILE_ID / false,
    // which causes companion-side IsForegroundSubProfileId checks to reject all requests.
    // This fake treats every sub profile as foreground, so companion-side handlers proceed
    // through the normal code path.
    int32_t GetForegroundSubProfileId(UserId userId) const override
    {
        (void)userId;
        return INVALID_SUB_PROFILE_ID;
    }

    std::optional<std::string> GetSubProfileName(const UserKey &userKey) const override
    {
        (void)userKey;
        return "test-sub-profile";
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
        for (auto &cb : activeUserKeyChangeCallbacks_) {
            cb(UserKey { userId, INVALID_SUB_PROFILE_ID }, UserKeyEventType::USER_ID_SWITCHED);
        }
    }

private:
    UserId userId_ = 0;
    std::string userName_;
    std::string userTypeName_ { "normal" };
    std::vector<ActiveUserIdCallback> callbacks_;
    std::vector<UnlockedActiveUserKeyCallback> activeUserKeyChangeCallbacks_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_USER_KEY_MANAGER_H
