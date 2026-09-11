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

#include <gtest/gtest.h>

#include <memory>

#include "service_common.h"
#include "sub_profile_id_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_SUB_PROFILE_ID = 5;

} // namespace

class ConstantSubProfileIdManagerTest : public Test {
public:
    void SetUp() override
    {
        manager_ = ISubProfileIdManager::Create();
        ASSERT_NE(nullptr, manager_);
    }

    void TearDown() override
    {
        manager_.reset();
    }

protected:
    std::shared_ptr<ISubProfileIdManager> manager_;
};

// Create returns a non-null manager
HWTEST_F(ConstantSubProfileIdManagerTest, Create_001, TestSize.Level0)
{
    auto manager = ISubProfileIdManager::Create();
    EXPECT_NE(nullptr, manager);
}

// GetForegroundSubProfileId always returns INVALID_SUB_PROFILE_ID
HWTEST_F(ConstantSubProfileIdManagerTest, GetForegroundSubProfileId_ReturnsInvalid, TestSize.Level0)
{
    EXPECT_EQ(manager_->GetForegroundSubProfileId(TEST_USER_ID), INVALID_SUB_PROFILE_ID);
}

// GetForegroundSubProfileId with different user IDs still returns invalid
HWTEST_F(ConstantSubProfileIdManagerTest, GetForegroundSubProfileId_DifferentUsers, TestSize.Level0)
{
    EXPECT_EQ(manager_->GetForegroundSubProfileId(0), INVALID_SUB_PROFILE_ID);
    EXPECT_EQ(manager_->GetForegroundSubProfileId(TEST_USER_ID), INVALID_SUB_PROFILE_ID);
    EXPECT_EQ(manager_->GetForegroundSubProfileId(INT32_MAX), INVALID_SUB_PROFILE_ID);
}

// IsForegroundSubProfileId always returns false
HWTEST_F(ConstantSubProfileIdManagerTest, IsForegroundSubProfileId_ReturnsFalse, TestSize.Level0)
{
    EXPECT_FALSE(manager_->IsForegroundSubProfileId(TEST_USER_ID, TEST_SUB_PROFILE_ID));
}

// IsForegroundSubProfileId with invalid sub profile id returns false
HWTEST_F(ConstantSubProfileIdManagerTest, IsForegroundSubProfileId_InvalidId, TestSize.Level0)
{
    EXPECT_FALSE(manager_->IsForegroundSubProfileId(TEST_USER_ID, INVALID_SUB_PROFILE_ID));
}

// GetSubProfileName returns nullopt
HWTEST_F(ConstantSubProfileIdManagerTest, GetSubProfileName_ReturnsNullopt, TestSize.Level0)
{
    auto result = manager_->GetSubProfileName(TEST_USER_ID, TEST_SUB_PROFILE_ID);
    EXPECT_FALSE(result.has_value());
}

// GetSubProfileName with invalid sub profile id returns nullopt
HWTEST_F(ConstantSubProfileIdManagerTest, GetSubProfileName_InvalidId, TestSize.Level0)
{
    auto result = manager_->GetSubProfileName(TEST_USER_ID, INVALID_SUB_PROFILE_ID);
    EXPECT_FALSE(result.has_value());
}

// SubscribeSubProfileChanged returns a valid subscription
HWTEST_F(ConstantSubProfileIdManagerTest, SubscribeSubProfileChanged_ReturnsSubscription, TestSize.Level0)
{
    auto subscription = manager_->SubscribeSubProfileChanged(
        [](UserId userId, int32_t subProfileId, SubProfileEventType eventType) {
            (void)userId;
            (void)subProfileId;
            (void)eventType;
        });
    EXPECT_NE(nullptr, subscription);
}

// SubscribeSubProfileChanged with null callback returns valid subscription (constant impl ignores it)
HWTEST_F(ConstantSubProfileIdManagerTest, SubscribeSubProfileChanged_NullCallback, TestSize.Level0)
{
    auto subscription = manager_->SubscribeSubProfileChanged(nullptr);
    EXPECT_NE(nullptr, subscription);
}

// Subscription cleanup does not crash
HWTEST_F(ConstantSubProfileIdManagerTest, SubscriptionCleanup_NoCrash, TestSize.Level0)
{
    {
        auto subscription = manager_->SubscribeSubProfileChanged(
            [](UserId, int32_t, SubProfileEventType) {});
        ASSERT_NE(nullptr, subscription);
    }
    // subscription destroyed here, should not crash
    SUCCEED();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
