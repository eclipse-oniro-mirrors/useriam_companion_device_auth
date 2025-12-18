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
#include <memory>
#include <thread>

#include "relative_timer.h"
#include "resident_task_runner.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class ResidentTaskRunnerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ResidentTaskRunnerTest::SetUpTestCase()
{
}

void ResidentTaskRunnerTest::TearDownTestCase()
{
}

void ResidentTaskRunnerTest::SetUp()
{
}

void ResidentTaskRunnerTest::TearDown()
{
}

HWTEST_F(ResidentTaskRunnerTest, PostTask_001, TestSize.Level0)
{
    auto runner = std::make_shared<ResidentTaskRunner>();
    ASSERT_NE(runner, nullptr);

    bool taskExecuted = false;
    runner->PostTask([&taskExecuted]() { taskExecuted = true; });

    RelativeTimer::GetInstance().ExecuteAll();
    EXPECT_TRUE(taskExecuted);
}

HWTEST_F(ResidentTaskRunnerTest, Suspend_001, TestSize.Level0)
{
    auto runner = std::make_shared<ResidentTaskRunner>();
    ASSERT_NE(runner, nullptr);

    runner->Suspend();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
