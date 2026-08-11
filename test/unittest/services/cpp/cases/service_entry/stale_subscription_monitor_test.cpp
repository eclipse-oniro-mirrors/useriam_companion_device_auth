/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"

#include "relative_timer.h"
#include "service_common.h"
#include "stale_subscription_monitor.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint64_t MIN_MS = 60 * 1000;
constexpr uint64_t HOUR_MS = 60 * MIN_MS;
constexpr int32_t TEST_CALLER_PID = 1234;
constexpr int32_t TEST_CALLER_UID = 100;

CallerInfo MakeCaller(const std::string &name)
{
    CallerInfo info;
    info.name = name;
    info.pid = TEST_CALLER_PID;
    info.uid = TEST_CALLER_UID;
    info.tokenId = 0xdeadbeef;
    info.type = CallerTokenType::Hap;
    return info;
}

void LinkTimerToTimeKeeper(MockTimeKeeper &timeKeeper)
{
    RelativeTimer::GetInstance().SetTimeProvider(
        [&timeKeeper]() -> uint64_t { return timeKeeper.GetSteadyTimeMs().value_or(0); });
}

// Advance steady time then drive one stale scan through the real timer path: the periodic scan
// timer fires its callback (which posts OnScanTimer to the resident runner), and the fake
// TaskRunnerManager drains it synchronously.
void AdvanceAndScan(MockTimeKeeper &timeKeeper, uint64_t ms)
{
    timeKeeper.AdvanceSteadyTime(ms);
    RelativeTimer::GetInstance().DrainExpiredTasks();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
}

class StaleSubscriptionMonitorTest : public Test {
public:
    void SetUp() override
    {
        guard_ = std::make_unique<MockGuard>();
        LinkTimerToTimeKeeper(guard_->GetTimeKeeper());
    }

    void TearDown() override
    {
        guard_.reset();
    }

    std::shared_ptr<StaleSubscriptionMonitor> monitor_ = StaleSubscriptionMonitor::Create();
    std::unique_ptr<MockGuard> guard_;
};

// No report before the subscription has been held 1h.
HWTEST_F(StaleSubscriptionMonitorTest, NoReport_Before1h, TestSize.Level0)
{
    EXPECT_CALL(guard_->GetEventManagerAdapter(),
        ReportSystemFault(StrEq("STALE_SUBSCRIPTION"), StrEq("com.test.app"), _))
        .Times(0);

    auto token = monitor_->AddSubscription(MakeCaller("com.test.app"));

    AdvanceAndScan(guard_->GetTimeKeeper(), 59 * MIN_MS); // 59min: below 1h threshold
}

// If the steady clock regresses below the subscribe time, the raw age subtraction would underflow
// to ~UINT64_MAX and trip a false stale report. SafeSub must clamp this to "skip" instead. The scan
// is driven directly (tests compile with private=public) so the clock can jump backward without the
// fake RelativeTimer's forward-only scheduling getting in the way.
HWTEST_F(StaleSubscriptionMonitorTest, ClockRegression_NoFalseReport, TestSize.Level0)
{
    EXPECT_CALL(guard_->GetEventManagerAdapter(), ReportSystemFault(StrEq("STALE_SUBSCRIPTION"), _, _)).Times(0);

    // Seed a non-zero subscribe time so the clock can later regress below it.
    guard_->GetTimeKeeper().SetSteadyTime(HOUR_MS);
    auto token = monitor_->AddSubscription(MakeCaller("com.test.app")); // subscribeTimeMs = 1h

    guard_->GetTimeKeeper().SetSteadyTime(MIN_MS); // clock regresses: now (1min) < subscribeTimeMs (1h)
    monitor_->OnScanTimer();                       // raw subtraction would underflow -> false report
}

// First report fires once the 1h threshold is crossed, carries the holder identity, and
// includes the foreground field (no query set -> foreground:0).
HWTEST_F(StaleSubscriptionMonitorTest, FirstReport_After1h_ContainsCallerInfo, TestSize.Level0)
{
    EXPECT_CALL(guard_->GetEventManagerAdapter(),
        ReportSystemFault(StrEq("STALE_SUBSCRIPTION"), StrEq("com.test.app"),
            AllOf(HasSubstr("pid:1234"), HasSubstr("ageSec:"), HasSubstr("foreground:"))))
        .Times(1);

    auto token = monitor_->AddSubscription(MakeCaller("com.test.app"));

    AdvanceAndScan(guard_->GetTimeKeeper(), 61 * MIN_MS); // 61min: crosses 1h threshold
}

// When the adapter reports the caller bundle as watched and foreground, the report encodes it.
HWTEST_F(StaleSubscriptionMonitorTest, ForegroundApp_ReportedAsForeground, TestSize.Level0)
{
    EXPECT_CALL(guard_->GetEventManagerAdapter(),
        ReportSystemFault(StrEq("STALE_SUBSCRIPTION"), StrEq("com.test.app"), HasSubstr("foreground:1")))
        .Times(1);
    ON_CALL(guard_->GetAppForegroundStateAdapter(), GetForegroundWatchedApps())
        .WillByDefault(Return(std::vector<std::string> { "com.test.app" }));

    auto token = monitor_->AddSubscription(MakeCaller("com.test.app"));

    AdvanceAndScan(guard_->GetTimeKeeper(), 61 * MIN_MS);
}

// After the first report, no re-report within the 24h (daily) gap.
HWTEST_F(StaleSubscriptionMonitorTest, NoReReport_Within24h, TestSize.Level0)
{
    EXPECT_CALL(guard_->GetEventManagerAdapter(),
        ReportSystemFault(StrEq("STALE_SUBSCRIPTION"), StrEq("com.test.app"), _))
        .Times(1);

    auto token = monitor_->AddSubscription(MakeCaller("com.test.app"));

    AdvanceAndScan(guard_->GetTimeKeeper(), 61 * MIN_MS); // first report
    AdvanceAndScan(guard_->GetTimeKeeper(), 1 * HOUR_MS); // 1h later: within 24h gap, no re-report
}

// Re-report only after the 24h daily gap has elapsed since the previous report.
HWTEST_F(StaleSubscriptionMonitorTest, ReReport_After24h, TestSize.Level0)
{
    EXPECT_CALL(guard_->GetEventManagerAdapter(),
        ReportSystemFault(StrEq("STALE_SUBSCRIPTION"), StrEq("com.test.app"), _))
        .Times(2);

    auto token = monitor_->AddSubscription(MakeCaller("com.test.app"));

    AdvanceAndScan(guard_->GetTimeKeeper(), 61 * MIN_MS);           // first report
    AdvanceAndScan(guard_->GetTimeKeeper(), 24 * HOUR_MS + MIN_MS); // >24h later: re-report
}

// Dropping the returned token (RAII release) erases the record, so no further reports.
HWTEST_F(StaleSubscriptionMonitorTest, ReleaseToken_StopsReports, TestSize.Level0)
{
    EXPECT_CALL(guard_->GetEventManagerAdapter(),
        ReportSystemFault(StrEq("STALE_SUBSCRIPTION"), StrEq("com.test.app"), _))
        .Times(1);

    auto token = monitor_->AddSubscription(MakeCaller("com.test.app"));

    AdvanceAndScan(guard_->GetTimeKeeper(), 61 * MIN_MS);           // first report
    token.reset();                                                  // RAII release: record erased
    AdvanceAndScan(guard_->GetTimeKeeper(), 24 * HOUR_MS + MIN_MS); // no further report
}

// Each Register returns an independent token with its own subscribe time; both are tracked, so
// once each crosses the 1h threshold it reports on its own.
HWTEST_F(StaleSubscriptionMonitorTest, TwoRegistrations_ReportIndependently, TestSize.Level0)
{
    EXPECT_CALL(guard_->GetEventManagerAdapter(),
        ReportSystemFault(StrEq("STALE_SUBSCRIPTION"), StrEq("com.test.app"), _))
        .Times(2);

    auto token1 = monitor_->AddSubscription(MakeCaller("com.test.app"));
    guard_->GetTimeKeeper().AdvanceSteadyTime(30 * MIN_MS);
    auto token2 = monitor_->AddSubscription(MakeCaller("com.test.app"));
    // token1 aged 91min, token2 aged 61min -> both >= 1h, both report independently.
    AdvanceAndScan(guard_->GetTimeKeeper(), 61 * MIN_MS);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
