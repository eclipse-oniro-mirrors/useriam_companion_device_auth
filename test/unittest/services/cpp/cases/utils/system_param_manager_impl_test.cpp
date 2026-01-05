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

#include <memory>

#include <gtest/gtest.h>

#include "relative_timer.h"
#include "singleton_manager.h"
#include "system_param_manager_impl.h"
#include "task_runner_manager.h"

#include "mock_misc_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SystemParamManagerImplTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        ON_CALL(mockMiscManager_, GetNextGlobalId()).WillByDefault([]() {
            static int32_t id = 1;
            return id++;
        });
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockMiscManager> mockMiscManager_;
};

HWTEST_F(SystemParamManagerImplTest, Create_001, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    EXPECT_NE(nullptr, manager);
}

HWTEST_F(SystemParamManagerImplTest, GetParam_001, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::string value = manager->GetParam("test.key", "default_value");
    EXPECT_TRUE(value.empty());
}

HWTEST_F(SystemParamManagerImplTest, SetParam_001, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->SetParam("test.key", "test_value");
}

HWTEST_F(SystemParamManagerImplTest, SetParam_002, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->SetParam("", "");
}

HWTEST_F(SystemParamManagerImplTest, SetParamTwice_001, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->SetParamTwice("test.key", "value1", "value2");
}

HWTEST_F(SystemParamManagerImplTest, SetParamTwice_002, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->SetParamTwice("", "", "");
}

HWTEST_F(SystemParamManagerImplTest, WatchParam_001, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    bool callbackCalled = false;
    std::string receivedValue;

    auto subscription =
        manager->WatchParam("test.watch.key", [&callbackCalled, &receivedValue](const std::string &value) {
            callbackCalled = true;
            receivedValue = value;
        });

    EXPECT_NE(nullptr, subscription);
}

HWTEST_F(SystemParamManagerImplTest, WatchParam_002, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto subscription = manager->WatchParam("test.watch.key", nullptr);
    EXPECT_EQ(nullptr, subscription);
}

HWTEST_F(SystemParamManagerImplTest, WatchParam_003, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    bool callbackCalled1 = false;
    bool callbackCalled2 = false;

    auto subscription1 =
        manager->WatchParam("test.watch.key", [&callbackCalled1](const std::string &value) { callbackCalled1 = true; });

    auto subscription2 =
        manager->WatchParam("test.watch.key", [&callbackCalled2](const std::string &value) { callbackCalled2 = true; });

    EXPECT_NE(nullptr, subscription1);
    EXPECT_NE(nullptr, subscription2);
}

HWTEST_F(SystemParamManagerImplTest, WatchParam_004, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    {
        auto subscription = manager->WatchParam("test.watch.key", [](const std::string &value) {});
        EXPECT_NE(nullptr, subscription);
    }
}

HWTEST_F(SystemParamManagerImplTest, OnParamChange_001, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    bool callbackCalled = false;
    std::string receivedValue;

    auto subscription =
        manager->WatchParam("test.watch.key", [&callbackCalled, &receivedValue](const std::string &value) {
            callbackCalled = true;
            receivedValue = value;
        });

    ASSERT_NE(nullptr, subscription);

    manager->OnParamChange("test.watch.key", "new_value");

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ("new_value", receivedValue);
}

HWTEST_F(SystemParamManagerImplTest, OnParamChange_002, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->OnParamChange("non.watched.key", "some_value");

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SystemParamManagerImplTest, OnParamChange_003, TestSize.Level0)
{
    auto manager = SystemParamManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    bool callbackCalled = false;

    {
        auto subscription = manager->WatchParam("test.watch.key",
            [&callbackCalled](const std::string &value) { callbackCalled = true; });

        ASSERT_NE(nullptr, subscription);
    }

    manager->OnParamChange("test.watch.key", "new_value");

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackCalled);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
