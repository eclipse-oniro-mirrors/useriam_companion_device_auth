/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <functional>
#include <memory>
#include <string>

#include "system_ability_definition.h"
#include "system_ability_listener.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

constexpr int32_t INT32_2 = 2;
namespace {
constexpr int32_t INT32_0 = 0;
constexpr int32_t INT32_8888 = 8888;
constexpr int32_t INT32_9999 = 9999;
} // namespace

class SystemAbilityListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void SystemAbilityListenerTest::SetUpTestCase()
{
}

void SystemAbilityListenerTest::TearDownTestCase()
{
}

void SystemAbilityListenerTest::SetUp()
{
}

void SystemAbilityListenerTest::TearDown()
{
}

/**
 * @brief Test OnAddSystemAbility calls the add callback function.
 */
HWTEST_F(SystemAbilityListenerTest, OnAddSystemAbilityCallsAddCallback, TestSize.Level0)
{
    // Arrange
    bool addCallbackCalled = false;
    bool removeCallbackCalled = false;

    sptr<SystemAbilityListener> listener = new (std::nothrow) SystemAbilityListener(
        "TestService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH,
        [&addCallbackCalled]() { addCallbackCalled = true; },
        [&removeCallbackCalled]() { removeCallbackCalled = true; });

    ASSERT_NE(listener, nullptr);

    // Act
    listener->OnAddSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "test-device");

    // Assert
    EXPECT_TRUE(addCallbackCalled);
    EXPECT_FALSE(removeCallbackCalled);
}

/**
 * @brief Test OnRemoveSystemAbility calls the remove callback function.
 */
HWTEST_F(SystemAbilityListenerTest, OnRemoveSystemAbilityCallsRemoveCallback, TestSize.Level0)
{
    // Arrange
    bool addCallbackCalled = false;
    bool removeCallbackCalled = false;

    sptr<SystemAbilityListener> listener = new (std::nothrow) SystemAbilityListener(
        "TestService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH,
        [&addCallbackCalled]() { addCallbackCalled = true; },
        [&removeCallbackCalled]() { removeCallbackCalled = true; });

    ASSERT_NE(listener, nullptr);

    // Act
    listener->OnRemoveSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "test-device");

    // Assert
    EXPECT_FALSE(addCallbackCalled);
    EXPECT_TRUE(removeCallbackCalled);
}

/**
 * @brief Test OnAddSystemAbility ignores different systemAbilityId.
 */
HWTEST_F(SystemAbilityListenerTest, OnAddSystemAbilityIgnoresDifferentSaId, TestSize.Level0)
{
    // Arrange
    bool addCallbackCalled = false;

    sptr<SystemAbilityListener> listener = new (std::nothrow) SystemAbilityListener(
        "TestService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH,
        [&addCallbackCalled]() { addCallbackCalled = true; }, []() {});

    ASSERT_NE(listener, nullptr);

    // Act - Call with different SA ID
    listener->OnAddSystemAbility(INT32_9999, "test-device");

    // Assert
    EXPECT_FALSE(addCallbackCalled);
}

/**
 * @brief Test OnRemoveSystemAbility ignores different systemAbilityId.
 */
HWTEST_F(SystemAbilityListenerTest, OnRemoveSystemAbilityIgnoresDifferentSaId, TestSize.Level0)
{
    // Arrange
    bool removeCallbackCalled = false;

    sptr<SystemAbilityListener> listener = new (std::nothrow) SystemAbilityListener(
        "TestService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, []() {},
        [&removeCallbackCalled]() { removeCallbackCalled = true; });

    ASSERT_NE(listener, nullptr);

    // Act - Call with different SA ID
    listener->OnRemoveSystemAbility(INT32_8888, "test-device");

    // Assert
    EXPECT_FALSE(removeCallbackCalled);
}

/**
 * @brief Test with nullptr callbacks (should not crash).
 */
HWTEST_F(SystemAbilityListenerTest, NullptrCallbacksDoesNotCrash, TestSize.Level0)
{
    // Arrange
    sptr<SystemAbilityListener> listener = new (std::nothrow)
        SystemAbilityListener("TestService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, nullptr, nullptr);

    ASSERT_NE(listener, nullptr);

    // Act - Should not crash
    listener->OnAddSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "test-device");
    listener->OnRemoveSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "test-device");

    // Assert - No crash is success
    EXPECT_TRUE(true);
}

/**
 * @brief Test multiple OnAdd/OnRemove cycles.
 */
HWTEST_F(SystemAbilityListenerTest, MultipleAddRemoveCycles, TestSize.Level0)
{
    // Arrange
    int addCount = 0;
    int removeCount = 0;

    sptr<SystemAbilityListener> listener = new (std::nothrow) SystemAbilityListener(
        "TestService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, [&addCount]() { addCount++; },
        [&removeCount]() { removeCount++; });

    ASSERT_NE(listener, nullptr);

    // Act - Multiple cycles
    listener->OnAddSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "device1");
    listener->OnRemoveSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "device1");
    listener->OnAddSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "device2");
    listener->OnRemoveSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "device2");

    // Assert
    EXPECT_EQ(addCount, INT32_2);
    EXPECT_EQ(removeCount, INT32_2);
}

/**
 * @brief Test Subscribe static method.
 */
HWTEST_F(SystemAbilityListenerTest, SubscribeReturnsValidListener, TestSize.Level0)
{
    // Arrange - Prepare callbacks
    bool addCallbackCalled = false;
    bool removeCallbackCalled = false;

    // Act - Subscribe creates and returns a listener
    sptr<SystemAbilityListener> listener = SystemAbilityListener::Subscribe(
        "TestService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH,
        [&addCallbackCalled]() { addCallbackCalled = true; },
        [&removeCallbackCalled]() { removeCallbackCalled = true; });

    // Assert - Should return a valid listener
    ASSERT_NE(listener, nullptr);

    // Trigger callback manually to test
    listener->OnAddSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, "test-device");
    EXPECT_TRUE(addCallbackCalled);
    EXPECT_FALSE(removeCallbackCalled);
}

/**
 * @brief Test UnSubscribe static method.
 */
HWTEST_F(SystemAbilityListenerTest, UnSubscribeSucceeds, TestSize.Level0)
{
    // Arrange - Create a listener via Subscribe
    sptr<SystemAbilityListener> listener = SystemAbilityListener::Subscribe(
        "TestService", SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, []() {}, []() {});

    ASSERT_NE(listener, nullptr);

    // Act - UnSubscribe should succeed
    int32_t result = SystemAbilityListener::UnSubscribe(SUBSYS_USERIAM_SYS_ABILITY_COMPANIONDEVICEAUTH, listener);

    // Assert - Should return success (0)
    EXPECT_EQ(result, INT32_0);
}
