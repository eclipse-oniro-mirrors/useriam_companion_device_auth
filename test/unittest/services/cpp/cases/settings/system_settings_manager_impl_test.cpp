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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

#include "mock_guard.h"
#include "mock_remote_object.h"

#include "datashare_helper.h"
#include "datashare_result_set.h"
#include "system_settings_manager_impl.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t VALID_USER_ID = 100;
constexpr int32_t OTHER_USER_ID = 101;
constexpr int32_t INVALID_USER_ID = -1;
constexpr int SUBSCRIBER2_WEIGHT = 10;

sptr<IRemoteObject> MakeServiceToken()
{
    return sptr<IRemoteObject>(new MockRemoteObject());
}

// The watcher registers one active-user callback during Create(); capture it into `out` so a test can
// simulate a user switch or late arrival. The Invoke returns a valid no-op Subscription like the mock
// default so Init() succeeds.
void CaptureActiveUserCallback(MockUserIdManager &mock, ActiveUserIdCallback &out)
{
    EXPECT_CALL(mock, SubscribeUnlockedActiveUserId(_))
        .WillRepeatedly(DoAll(SaveArg<0>(&out),
            Invoke([](ActiveUserIdCallback &&) { return std::make_unique<Subscription>([]() {}); })));
}

// Counts registered observers whose URI targets the given user. Robust to Uri re-serialization since it
// only matches the USER_SETTINGSDATA_SECURE_<userId> path segment.
size_t CountObserversForUser(int32_t userId)
{
    std::string token = "USER_SETTINGSDATA_SECURE_" + std::to_string(userId);
    size_t n = 0;
    for (const auto &entry : OHOS::DataShare::g_registeredObservers) {
        if (entry.first.find(token) != std::string::npos) {
            ++n;
        }
    }
    return n;
}

class SystemSettingsManagerImplTest : public Test {
protected:
    // Create() registers DataShare observers via the fake helper (tracked globally), and tests may seed
    // fake query results. Reset all fake state between cases so nothing leaks across cases.
    void TearDown() override
    {
        OHOS::DataShare::ResetDataShareFake();
        TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    }
};

HWTEST_F(SystemSettingsManagerImplTest, Create_ReturnsNonNull, TestSize.Level0)
{
    MockGuard guard;
    auto manager = SystemSettingsManagerImpl::Create(MakeServiceToken());
    ASSERT_NE(manager, nullptr);
}

HWTEST_F(SystemSettingsManagerImplTest, GetSettingsValue_InvalidUserId_ReturnsEmpty, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserId()).WillRepeatedly(Return(INVALID_USER_ID));

    auto manager = SystemSettingsManagerImpl::Create(MakeServiceToken());
    ASSERT_NE(manager, nullptr);

    // No active user at Init → observer never registers → cache stays empty.
    EXPECT_EQ(manager->GetSettingsValue(SettingKey::DisplayDeviceName), "");
}

HWTEST_F(SystemSettingsManagerImplTest, GetSettingsValue_EmptySettings_ReturnsEmpty, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserId()).WillRepeatedly(Return(VALID_USER_ID));

    auto token = MakeServiceToken();
    auto manager = SystemSettingsManagerImpl::Create(token);
    ASSERT_NE(manager, nullptr);

    // No value seeded → DataShare reports the row absent → the cache backfills "" → GetSettingsValue
    // returns "" (the display-name sysparam fallback now lives in the caller, not the generic manager).
    EXPECT_EQ(manager->GetSettingsValue(SettingKey::DisplayDeviceName), "");
}

HWTEST_F(SystemSettingsManagerImplTest, GetSettingsValue_ReturnsCachedValue, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserId()).WillRepeatedly(Return(VALID_USER_ID));
    OHOS::DataShare::SetSettingsValue(VALID_USER_ID, "settings.general.display_device_name", "MyPhone");

    // Keep the service token alive: Create() only stores a weak reference, and Init() promotes it
    // again when it opens the DataShareHelper to register the observer and backfill the cache.
    auto token = MakeServiceToken();
    auto manager = SystemSettingsManagerImpl::Create(token);
    ASSERT_NE(manager, nullptr);

    // Init() subscribed + cached the active user's value; GetSettingsValue is now a memory read.
    EXPECT_EQ(manager->GetSettingsValue(SettingKey::DisplayDeviceName), "MyPhone");
}

HWTEST_F(SystemSettingsManagerImplTest, SubscribeSettingsChange_FiresOnDataChange, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserId()).WillRepeatedly(Return(VALID_USER_ID));
    // Keep the service token alive: Create() stores only a weak reference, and Init() promotes it
    // again when it opens the DataShareHelper to register the observer.
    auto token = MakeServiceToken();
    auto manager = SystemSettingsManagerImpl::Create(token);
    ASSERT_NE(manager, nullptr);

    bool fired = false;
    auto subscription = manager->SubscribeSettingsChange(SettingKey::DisplayDeviceName, [&fired]() { fired = true; });
    ASSERT_NE(subscription, nullptr);
    // Create() registered the observer (under ENABLE_TEST) with the fake helper at Init; Subscribe only
    // adds the callback to the fan-out.
    ASSERT_NE(OHOS::DataShare::g_lastRegisteredObserver, nullptr);

    // Simulate a display_device_name write: the observer hops to the resident runner, which refreshes
    // the cache and fans out to subscribers. EnsureAllTaskExecuted drains the OnChange chain.
    OHOS::DataShare::g_lastRegisteredObserver->OnChange();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(fired);

    // After unsubscribing, a further change must not fire the callback.
    fired = false;
    subscription.reset();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted(); // drain the async callback removal
    OHOS::DataShare::g_lastRegisteredObserver->OnChange();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_FALSE(fired);
}

HWTEST_F(SystemSettingsManagerImplTest, Subscribe_MultipleSubscribers_AllFire, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserId()).WillRepeatedly(Return(VALID_USER_ID));
    auto token = MakeServiceToken();
    auto manager = SystemSettingsManagerImpl::Create(token);
    ASSERT_NE(manager, nullptr);

    int fired = 0;
    auto sub1 = manager->SubscribeSettingsChange(SettingKey::DisplayDeviceName, [&fired]() { fired += 1; });
    auto sub2 =
        manager->SubscribeSettingsChange(SettingKey::DisplayDeviceName, [&fired]() { fired += SUBSCRIBER2_WEIGHT; });
    ASSERT_NE(sub1, nullptr);
    ASSERT_NE(sub2, nullptr);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    ASSERT_NE(OHOS::DataShare::g_lastRegisteredObserver, nullptr);

    // A single row change fans out to every subscriber for the setting.
    OHOS::DataShare::g_lastRegisteredObserver->OnChange();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(fired, 1 + SUBSCRIBER2_WEIGHT);

    // Unsubscribe one; the other must keep firing.
    fired = 0;
    sub1.reset();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    OHOS::DataShare::g_lastRegisteredObserver->OnChange();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(fired, SUBSCRIBER2_WEIGHT);
}

HWTEST_F(SystemSettingsManagerImplTest, Subscribe_RePointsObserverOnActiveUserSwitch, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserId()).WillRepeatedly(Return(VALID_USER_ID));
    ActiveUserIdCallback activeUserCb;
    CaptureActiveUserCallback(guard.GetUserIdManager(), activeUserCb);
    auto token = MakeServiceToken();
    auto manager = SystemSettingsManagerImpl::Create(token);
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeSettingsChange(SettingKey::DisplayDeviceName, []() {});
    ASSERT_NE(subscription, nullptr);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    // Init() registered the observer against the initial active user (100).
    EXPECT_EQ(CountObserversForUser(VALID_USER_ID), 1u);
    EXPECT_EQ(CountObserversForUser(OTHER_USER_ID), 0u);

    // Switch the active user: the watcher must unregister the old-user observer and re-point to the new.
    activeUserCb(OTHER_USER_ID);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(CountObserversForUser(VALID_USER_ID), 0u);
    EXPECT_EQ(CountObserversForUser(OTHER_USER_ID), 1u);
    EXPECT_EQ(OHOS::DataShare::g_registeredObservers.size(), 1u); // re-pointed, not duplicated
}

HWTEST_F(SystemSettingsManagerImplTest, Subscribe_DefersObserverUntilActiveUserArrives, TestSize.Level0)
{
    MockGuard guard;
    // Boot race: the SA starts before any user is active, so the observer cannot register.
    EXPECT_CALL(guard.GetUserIdManager(), GetUnlockedActiveUserId()).WillRepeatedly(Return(INVALID_USER_ID));
    ActiveUserIdCallback activeUserCb;
    CaptureActiveUserCallback(guard.GetUserIdManager(), activeUserCb);
    auto token = MakeServiceToken();
    auto manager = SystemSettingsManagerImpl::Create(token);
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeSettingsChange(SettingKey::DisplayDeviceName, []() {});
    ASSERT_NE(subscription, nullptr);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(OHOS::DataShare::g_registeredObservers.empty()); // deferred — no active user yet

    // A user arrives later: the deferred observer must now register against it.
    activeUserCb(VALID_USER_ID);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(CountObserversForUser(VALID_USER_ID), 1u);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
