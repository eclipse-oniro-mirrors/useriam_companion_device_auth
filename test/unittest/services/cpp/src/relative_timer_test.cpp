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

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#include "relative_timer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class RelativeTimerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void RelativeTimerTest::SetUpTestCase()
{
}

void RelativeTimerTest::TearDownTestCase()
{
}

void RelativeTimerTest::SetUp()
{
}

void RelativeTimerTest::TearDown()
{
}

HWTEST_F(RelativeTimerTest, Register_001, TestSize.Level0)
{
    auto &timer = RelativeTimer::GetInstance();
    bool callbackExecuted = false;

    auto subscription = timer.Register([&callbackExecuted]() { callbackExecuted = true; }, 50);

    EXPECT_NE(subscription, nullptr);
    RelativeTimer::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackExecuted);
}

HWTEST_F(RelativeTimerTest, RegisterPeriodic_001, TestSize.Level0)
{
    auto &timer = RelativeTimer::GetInstance();
    int count = 0;

    auto subscription = timer.RegisterPeriodic([&count]() { count++; }, 30);

    RelativeTimer::GetInstance().ExecuteAll();
    EXPECT_EQ(1, count);
}

HWTEST_F(RelativeTimerTest, PostTask_001, TestSize.Level0)
{
    auto &timer = RelativeTimer::GetInstance();
    bool taskExecuted = false;

    timer.PostTask([&taskExecuted]() { taskExecuted = true; }, 50);

    RelativeTimer::GetInstance().ExecuteAll();
    EXPECT_TRUE(taskExecuted);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
