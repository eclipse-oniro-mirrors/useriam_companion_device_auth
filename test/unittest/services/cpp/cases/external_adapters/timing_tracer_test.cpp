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

#include "timing_tracer.h"

#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr StageId STAGE_A = 1;
constexpr StageId STAGE_B = 2;
} // namespace

class TimingTracerTest : public testing::Test {
public:
    void SetUp() override
    {
        guard_ = std::make_unique<MockGuard>();
        guard_->GetTimeKeeper().SetSteadyTime(0);
    }
    void TearDown() override
    {
        guard_.reset();
    }

    std::unique_ptr<MockGuard> guard_;
};

// Not started: all accessors return zero/empty.
HWTEST_F(TimingTracerTest, NotStarted, TestSize.Level0)
{
    TimingTracer tracer;
    EXPECT_FALSE(tracer.Started());
    EXPECT_EQ(tracer.TotalMs(), 0u);
    EXPECT_EQ(tracer.LocalMs(), 0u);
    EXPECT_TRUE(tracer.ExportTrace().empty());
}

// Start then Finish with no time advanced: zero duration.
HWTEST_F(TimingTracerTest, StartFinishZero, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    EXPECT_TRUE(tracer.Started());
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 0u);
}

// Basic total duration.
HWTEST_F(TimingTracerTest, TotalDuration, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(100);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 100u);
}

// Local only (no wait): Local == Total.
HWTEST_F(TimingTracerTest, LocalEqualsTotalWhenNoWait, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(100);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 100u);
    EXPECT_EQ(tracer.LocalMs(), 100u);
}

// Mark records timeline points; ExportTrace is "id:delta,..." relative to START.
HWTEST_F(TimingTracerTest, MarkExportTrace, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(50);
    tracer.Mark(STAGE_A);
    guard_->GetTimeKeeper().AdvanceSteadyTime(30);
    tracer.Mark(STAGE_B);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 80u);
    EXPECT_EQ(tracer.ExportTrace(), "1:50,2:80");
}

// Paired EnterWait/ExitWait: wait subtracted, Local = Total - wait.
HWTEST_F(TimingTracerTest, PairedWait, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(10); // local 10
    tracer.EnterWait(STAGE_A);
    guard_->GetTimeKeeper().AdvanceSteadyTime(40); // wait 40
    tracer.ExitWait(STAGE_A);
    guard_->GetTimeKeeper().AdvanceSteadyTime(20); // local 20
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 70u);
    EXPECT_EQ(tracer.LocalMs(), 30u); // 70 - 40
    // WAIT_BEGIN and WAIT_END both appear in the trace.
    EXPECT_EQ(tracer.ExportTrace(), "1:10,1:50");
}

// Any next point (here a Mark) closes the current wait — the core robustness property:
// [EnterWait, next point] always counts as wait, regardless of what that next point is.
HWTEST_F(TimingTracerTest, WaitClosedByNextPoint, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(10);
    tracer.EnterWait(STAGE_A); // begin wait @10
    guard_->GetTimeKeeper().AdvanceSteadyTime(40);
    tracer.Mark(STAGE_B);                          // Mark closes the wait: +40
    guard_->GetTimeKeeper().AdvanceSteadyTime(20); // local after Mark
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 70u);
    EXPECT_EQ(tracer.LocalMs(), 30u); // 70 - 40
    EXPECT_EQ(tracer.ExportTrace(), "1:10,2:50");
}

// Consecutive waits: a later EnterWait closes the earlier one. Waits do not nest.
HWTEST_F(TimingTracerTest, ConsecutiveWait, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    tracer.EnterWait(STAGE_A); // enter @0
    guard_->GetTimeKeeper().AdvanceSteadyTime(20);
    tracer.EnterWait(STAGE_B); // closes A (+20), begins B @20
    guard_->GetTimeKeeper().AdvanceSteadyTime(30);
    tracer.ExitWait(STAGE_B); // closes B (+30) @50
    guard_->GetTimeKeeper().AdvanceSteadyTime(10);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 60u);
    EXPECT_EQ(tracer.LocalMs(), 10u); // 60 - (20 + 30) = 10
}

// Unclosed EnterWait is charged to END (timeout / failure scenario).
HWTEST_F(TimingTracerTest, UnclosedWaitChargedToEnd, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(5); // local 5
    tracer.EnterWait(STAGE_A);
    guard_->GetTimeKeeper().AdvanceSteadyTime(95); // wait never closed
    tracer.Finish();                               // charges (END - enter) = 95
    EXPECT_EQ(tracer.TotalMs(), 100u);
    EXPECT_EQ(tracer.LocalMs(), 5u); // 100 - 95
    // Only the WAIT_BEGIN point is recorded (no matching WAIT_END).
    EXPECT_EQ(tracer.ExportTrace(), "1:5");
}

// ExportTrace empty when only Start+Finish with no Mark/Enter/Exit.
HWTEST_F(TimingTracerTest, ExportTraceEmptyNoPoints, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(50);
    tracer.Finish();
    EXPECT_TRUE(tracer.ExportTrace().empty());
}

// Mark/Enter/Exit before Start are no-ops.
HWTEST_F(TimingTracerTest, RecordsBeforeStartNoOp, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Mark(STAGE_A);
    tracer.EnterWait(STAGE_B);
    tracer.ExitWait(STAGE_B);
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(10);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 10u);
    EXPECT_EQ(tracer.LocalMs(), 10u);
    EXPECT_TRUE(tracer.ExportTrace().empty());
}

// Spurious ExitWait (no preceding EnterWait) is harmless: no wait accounted.
HWTEST_F(TimingTracerTest, SpuriousExitWaitIsHarmless, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(10);
    tracer.ExitWait(STAGE_A);
    guard_->GetTimeKeeper().AdvanceSteadyTime(20);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 30u);
    EXPECT_EQ(tracer.LocalMs(), 30u);
    EXPECT_EQ(tracer.ExportTrace(), "1:10");
}

// Start re-entry resets state: old points/wait cleared, timing restarts from new START.
HWTEST_F(TimingTracerTest, StartResetsState, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(50);
    tracer.Mark(STAGE_A);
    tracer.EnterWait(STAGE_B);
    guard_->GetTimeKeeper().AdvanceSteadyTime(10);
    tracer.Start(); // second Start resets
    guard_->GetTimeKeeper().AdvanceSteadyTime(40);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 40u);
    EXPECT_EQ(tracer.LocalMs(), 40u);
    EXPECT_TRUE(tracer.ExportTrace().empty());
}

// A second Finish() re-stamps endMs_ to the later time (it is NOT idempotent): this is the
// tracer-level root of the double-report TOTAL_TIME/LOCAL_TIME inflation bug, now guarded at
// the collector level by InteractionEventCollector::Report's reported_ early-return.
HWTEST_F(TimingTracerTest, SecondFinishReStampsEnd, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(100);
    tracer.Finish();
    guard_->GetTimeKeeper().AdvanceSteadyTime(50);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 150u);
}

// LOCAL accumulates across multiple wait/local segments.
HWTEST_F(TimingTracerTest, LocalAccumulatesAcrossMultipleWaitSegments, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(10); // local1
    tracer.EnterWait(STAGE_A);
    guard_->GetTimeKeeper().AdvanceSteadyTime(20);
    tracer.ExitWait(STAGE_A);
    guard_->GetTimeKeeper().AdvanceSteadyTime(15); // local2
    tracer.EnterWait(STAGE_B);
    guard_->GetTimeKeeper().AdvanceSteadyTime(25);
    tracer.ExitWait(STAGE_B);
    guard_->GetTimeKeeper().AdvanceSteadyTime(5); // local3
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 75u);
    EXPECT_EQ(tracer.LocalMs(), 30u); // 10 + 15 + 5
    EXPECT_EQ(tracer.ExportTrace(), "1:10,1:30,2:45,2:70");
}

// LocalMs underflow protection: waitMs > total yields 0 instead of underflowing.
HWTEST_F(TimingTracerTest, LocalMsUnderflowProtection, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(10);
    tracer.EnterWait(STAGE_A);
    guard_->GetTimeKeeper().AdvanceSteadyTime(90);
    tracer.ExitWait(STAGE_A);                  // waitMs = 90
    guard_->GetTimeKeeper().SetSteadyTime(50); // regress clock below accumulated wait
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 50u);
    EXPECT_EQ(tracer.LocalMs(), 0u); // 50 < 90 -> clamped to 0
}

// Zero-length wait (ExitWait at the same instant as EnterWait) adds nothing.
HWTEST_F(TimingTracerTest, ZeroLengthWaitAddsNothing, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(10);
    tracer.EnterWait(STAGE_A);
    tracer.ExitWait(STAGE_A); // no advance
    guard_->GetTimeKeeper().AdvanceSteadyTime(20);
    tracer.Finish();
    EXPECT_EQ(tracer.TotalMs(), 30u);
    EXPECT_EQ(tracer.LocalMs(), 30u);
    EXPECT_EQ(tracer.ExportTrace(), "1:10,1:10");
}

// CommonStages connection-wait ids render as plain decimal in the trace.
HWTEST_F(TimingTracerTest, CommonStageIdRendersAsDecimal, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Start();
    guard_->GetTimeKeeper().AdvanceSteadyTime(10);
    tracer.Mark(static_cast<StageId>(101));
    guard_->GetTimeKeeper().AdvanceSteadyTime(20);
    tracer.Mark(static_cast<StageId>(102));
    tracer.Finish();
    EXPECT_EQ(tracer.ExportTrace(), "101:10,102:30");
}

// Finish before Start is a no-op (completes the no-op trio with RecordsBeforeStartNoOp).
HWTEST_F(TimingTracerTest, FinishBeforeStartNoOp, TestSize.Level0)
{
    TimingTracer tracer;
    tracer.Finish();
    EXPECT_FALSE(tracer.Started());
    EXPECT_EQ(tracer.TotalMs(), 0u);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
