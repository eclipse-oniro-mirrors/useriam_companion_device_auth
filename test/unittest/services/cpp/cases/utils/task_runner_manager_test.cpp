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

#include <memory>

#include <gtest/gtest.h>

#include "mock_guard.h"

#include "resident_task_runner.h"
#include "task_runner_manager.h"
#include "temporary_task_runner.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class TaskRunnerManagerTest : public Test {
protected:
    void TearDown() override
    {
        // Execute all pending tasks so temporary runners are cleaned up.
        TaskRunnerManager::GetInstance().ExecuteAll();
    }
};

HWTEST_F(TaskRunnerManagerTest, PostOneShotTask_SucceedsAndRuns, TestSize.Level0)
{
    MockGuard guard;
    auto &trm = TaskRunnerManager::GetInstance();

    auto ran = std::make_shared<bool>(false);
    EXPECT_TRUE(trm.PostOneShotTask("one_shot_owner", TaskBlockPolicy::FATAL,
        [ran]() { *ran = true; }));

    trm.ExecuteAll();
    EXPECT_TRUE(*ran);
}

// GetBlockPolicy / GetOwner tests run against the real runner classes (not excluded from test
// builds): only TemporaryTaskRunner carries the knobs; ResidentTaskRunner pins FATAL and an
// empty owner explicitly, which is how "the resident thread ignores the policy" is enforced.
HWTEST_F(TaskRunnerManagerTest, GetBlockPolicy_TemporaryRunnerCarriesPolicy, TestSize.Level0)
{
    TemporaryTaskRunner reportRunner("policy_report_runner", "policy_owner", TaskBlockPolicy::REPORT);
    EXPECT_EQ(reportRunner.GetBlockPolicy(), TaskBlockPolicy::REPORT);

    TemporaryTaskRunner fatalRunner("policy_fatal_runner", "policy_owner", TaskBlockPolicy::FATAL);
    EXPECT_EQ(fatalRunner.GetBlockPolicy(), TaskBlockPolicy::FATAL);
}

HWTEST_F(TaskRunnerManagerTest, GetBlockPolicy_ResidentRunnerStaysFatal, TestSize.Level0)
{
    ResidentTaskRunner residentRunner;
    EXPECT_EQ(residentRunner.GetBlockPolicy(), TaskBlockPolicy::FATAL);
}

HWTEST_F(TaskRunnerManagerTest, GetOwner_TemporaryRunnerCarriesOwner, TestSize.Level0)
{
    TemporaryTaskRunner runner("owner_runner", "owner_a", TaskBlockPolicy::FATAL);
    EXPECT_EQ(runner.GetOwner(), "owner_a");
}

HWTEST_F(TaskRunnerManagerTest, GetOwner_ResidentRunnerHasNoOwner, TestSize.Level0)
{
    ResidentTaskRunner residentRunner;
    EXPECT_EQ(residentRunner.GetOwner(), "");
}

HWTEST_F(TaskRunnerManagerTest, RunTaskOnResidentSync_VoidCallable_ReturnsTrueAndRuns, TestSize.Level0)
{
    MockGuard guard;
    auto &trm = TaskRunnerManager::GetInstance();

    auto ran = std::make_shared<bool>(false);
    bool ok = trm.RunTaskOnResidentSync([ran]() { *ran = true; });
    EXPECT_TRUE(ok);
    EXPECT_TRUE(*ran);
}

HWTEST_F(TaskRunnerManagerTest, RunTaskOnResidentSync_ValueCallable_ReturnsOptional, TestSize.Level0)
{
    MockGuard guard;
    auto &trm = TaskRunnerManager::GetInstance();

    auto result = trm.RunTaskOnResidentSync([]() { return 0xABCD; });
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 0xABCD);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
