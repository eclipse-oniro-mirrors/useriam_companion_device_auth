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

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_ACTIVE_USER_ID_MANAGER_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_ACTIVE_USER_ID_MANAGER_H

#include <gmock/gmock.h>

#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockUserIdManager : public IUserIdManager {
public:
    MOCK_METHOD(bool, Initialize, (), ());
    MOCK_METHOD(int32_t, GetActiveUserId, (), (const, override));
    MOCK_METHOD(std::optional<std::string>, GetActiveUserName, (), (const, override));
    MOCK_METHOD(std::string, GetActiveUserTypeName, (), (const, override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeActiveUserId, (ActiveUserIdCallback && callback), (override));
    MOCK_METHOD(UserKey, GetUnlockedActiveUserkey, (), (const, override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeUnlockedActiveUserKey,
        (UnlockedActiveUserKeyCallback && callback), (override));
    MOCK_METHOD(bool, IsUserIdValid, (int32_t userId), (override));
    MOCK_METHOD(std::optional<std::vector<UserKey>>, GetAllValidUserKeys, (), (const, override));

    // Sub profile ID management
    MOCK_METHOD(int32_t, GetForegroundSubProfileId, (UserId userId), (const, override));
    MOCK_METHOD(bool, IsForegroundSubProfileId, (const UserKey &userKey), (const, override));
    MOCK_METHOD(std::optional<std::vector<int32_t>>, GetOsAccountSubProfileIds, (UserId userId), (const, override));
    MOCK_METHOD(std::optional<std::string>, GetSubProfileName, (const UserKey &userKey), (const, override));
    MOCK_METHOD(std::unique_ptr<Subscription>, SubscribeSubProfileChanged, (SubProfileChangedCallback && callback),
        (override));

    // Helper method to trigger the unlocked active user ID change callback in tests
    void NotifyUnlockedActiveUserKeyChanged(
        const UserKey &userKey = UserKey { INVALID_USER_ID, INVALID_SUB_PROFILE_ID })
    {
        if (unlockedUserIdCallback_) {
            unlockedUserIdCallback_(userKey);
        }
    }

    // Helper method to set up mock to store the callback for later invocation
    void SetupStoreUnlockedUserIdCallback()
    {
        ON_CALL(*this, SubscribeUnlockedActiveUserKey(testing::_))
            .WillByDefault(testing::Invoke([this](UnlockedActiveUserKeyCallback &&callback) {
                unlockedUserIdCallback_ = std::move(callback);
                return std::make_unique<Subscription>([]() {});
            }));
    }

    // Helper method to set up mock to store the sub profile changed callback for later invocation
    void SetupStoreSubProfileChangedCallback()
    {
        ON_CALL(*this, SubscribeSubProfileChanged(testing::_))
            .WillByDefault(testing::Invoke([this](SubProfileChangedCallback &&callback) {
                subProfileChangedCallback_ = std::move(callback);
                return std::make_unique<Subscription>([]() {});
            }));
    }

    // Helper method to trigger the sub profile changed callback in tests
    void NotifySubProfileChanged(const UserKey &userKey, SubProfileEventType eventType)
    {
        if (subProfileChangedCallback_) {
            subProfileChangedCallback_(userKey, eventType);
        }
    }

private:
    UnlockedActiveUserKeyCallback unlockedUserIdCallback_;
    SubProfileChangedCallback subProfileChangedCallback_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_ACTIVE_USER_ID_MANAGER_H
