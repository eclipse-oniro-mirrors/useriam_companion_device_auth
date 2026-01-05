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

#include <gtest/gtest.h>

#include "relative_timer.h"

using namespace OHOS::UserIam::CompanionDeviceAuth;

const uint32_t TEST_VAL100 = 100;
const uint32_t TEST_VAL50 = 50;

class RelativeTimerTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().Clear();
    }
};

TEST_F(RelativeTimerTest, ZeroDurationTaskExecutesImmediately)
{
    bool executed = false;
    auto subscription = RelativeTimer::GetInstance().Register([&executed]() { executed = true; }, 0);

    RelativeTimer::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(executed);
}

TEST_F(RelativeTimerTest, DelayedTaskNotExecutedWithoutFastForward)
{
    bool executed = false;
    auto subscription = RelativeTimer::GetInstance().Register([&executed]() { executed = true; }, TEST_VAL100);

    EXPECT_FALSE(executed);
}

TEST_F(RelativeTimerTest, DelayedTaskExecutedAfterFastForward)
{
    bool executed = false;
    auto subscription = RelativeTimer::GetInstance().Register([&executed]() { executed = true; }, TEST_VAL100);

    RelativeTimer::GetInstance().FastForward(TEST_VAL100);
    EXPECT_TRUE(executed);
}

TEST_F(RelativeTimerTest, PeriodicTaskExecutedMultipleTimes)
{
    int count = 0;
    auto subscription = RelativeTimer::GetInstance().RegisterPeriodic([&count]() { count++; }, TEST_VAL50);
    int testVal1 = 1;
    int testVal2 = 2;
    int testVal4 = 4;

    RelativeTimer::GetInstance().FastForward(TEST_VAL50);
    EXPECT_EQ(count, testVal1);

    RelativeTimer::GetInstance().FastForward(TEST_VAL50);
    EXPECT_EQ(count, testVal2);

    RelativeTimer::GetInstance().FastForward(TEST_VAL100);
    EXPECT_EQ(count, testVal4);
}

TEST_F(RelativeTimerTest, MultipleTasksExecuteInOrder)
{
    std::vector<int> order;
    int testVal1 = 1;
    int testVal2 = 2;
    int testVal3 = 3;
    size_t index2 = 2;
    auto sub1 = RelativeTimer::GetInstance().Register([&order]() { order.push_back(1); }, TEST_VAL100);
    auto sub2 = RelativeTimer::GetInstance().Register([&order]() { order.push_back(2); }, TEST_VAL100);
    auto sub3 = RelativeTimer::GetInstance().Register([&order]() { order.push_back(3); }, TEST_VAL50);

    RelativeTimer::GetInstance().FastForward(TEST_VAL50);
    EXPECT_EQ(order.size(), testVal1);
    EXPECT_EQ(order[0], testVal3);

    RelativeTimer::GetInstance().FastForward(TEST_VAL50);
    EXPECT_EQ(order.size(), testVal3);
    EXPECT_EQ(order[1], testVal1);
    EXPECT_EQ(order[index2], testVal2);
}

TEST_F(RelativeTimerTest, UnsubscribePreventsExecution)
{
    int count = 0;
    int testVal1 = 1;
    auto subscription = RelativeTimer::GetInstance().RegisterPeriodic([&count]() { count++; }, TEST_VAL100);

    RelativeTimer::GetInstance().FastForward(TEST_VAL100);
    EXPECT_EQ(count, testVal1);

    subscription.reset();

    RelativeTimer::GetInstance().FastForward(TEST_VAL100);
    EXPECT_EQ(count, testVal1);
}

TEST_F(RelativeTimerTest, PostTaskBehavior)
{
    bool executed = false;
    RelativeTimer::GetInstance().PostTask([&executed]() { executed = true; }, TEST_VAL100);

    RelativeTimer::GetInstance().FastForward(TEST_VAL100);
    EXPECT_TRUE(executed);
}

TEST_F(RelativeTimerTest, ExecuteAllImmediately)
{
    bool executed = false;
    RelativeTimer::GetInstance().PostTask([&executed]() { executed = true; }, 0);
    EXPECT_TRUE(executed);
}
