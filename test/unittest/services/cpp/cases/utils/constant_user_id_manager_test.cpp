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

#include <memory>

#include <gtest/gtest.h>

#include "adapter_manager.h"
#include "mock_time_keeper.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "user_id_manager.h"

using namespace testing;
using namespace testing::ext;

namespace {
}

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class ConstantUserIdManagerTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }
};

HWTEST_F(ConstantUserIdManagerTest, CreateUserIdManager_001, TestSize.Level0)
{
    auto manager = IUserIdManager::Create();
    EXPECT_NE(nullptr, manager);
}

HWTEST_F(ConstantUserIdManagerTest, GetActiveUserId_001, TestSize.Level0)
{
    auto manager = IUserIdManager::Create();
    ASSERT_NE(nullptr, manager);

    int32_t userId = manager->GetActiveUserId();
    EXPECT_EQ(100, userId);
}

HWTEST_F(ConstantUserIdManagerTest, GetActiveUserName_001, TestSize.Level0)
{
    auto manager = IUserIdManager::Create();
    ASSERT_NE(nullptr, manager);

    std::string userName = manager->GetActiveUserName();
    EXPECT_EQ("", userName);
}

HWTEST_F(ConstantUserIdManagerTest, SubscribeActiveUserId_001, TestSize.Level0)
{
    auto manager = IUserIdManager::Create();
    ASSERT_NE(nullptr, manager);

    bool callbackCalled = false;
    int32_t receivedUserId = 0;

    auto subscription = manager->SubscribeActiveUserId([&callbackCalled, &receivedUserId](UserId userId) {
        callbackCalled = true;
        receivedUserId = userId;
    });

    EXPECT_NE(nullptr, subscription);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(100, receivedUserId);
}

HWTEST_F(ConstantUserIdManagerTest, SubscribeActiveUserId_002, TestSize.Level0)
{
    auto manager = IUserIdManager::Create();
    ASSERT_NE(nullptr, manager);

    auto subscription = manager->SubscribeActiveUserId(nullptr);

    EXPECT_EQ(nullptr, subscription);
}

HWTEST_F(ConstantUserIdManagerTest, IsUserIdValid_001, TestSize.Level0)
{
    auto manager = IUserIdManager::Create();
    ASSERT_NE(nullptr, manager);

    bool isValid = manager->IsUserIdValid(100);
    EXPECT_TRUE(isValid);
}

HWTEST_F(ConstantUserIdManagerTest, IsUserIdValid_002, TestSize.Level0)
{
    auto manager = IUserIdManager::Create();
    ASSERT_NE(nullptr, manager);

    bool isValid = manager->IsUserIdValid(50);
    EXPECT_FALSE(isValid);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
