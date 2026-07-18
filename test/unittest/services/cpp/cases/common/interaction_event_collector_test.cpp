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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iam_common_defines.h"
#include "interaction_event_collector.h"
#include "mock_guard.h"
#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr StageId STAGE_A = 1;
constexpr StageId STAGE_B = 2;
constexpr StageId STAGE_C = 3;

class InteractionEventCollectorTest : public testing::Test {
public:
};

HWTEST_F(InteractionEventCollectorTest, SetAtl_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetAtl(UserAuth::ATL1);
    EXPECT_NE(collector.GetExtraInfo().find("ATL:"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetBindingId_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetBindingId(42);
    EXPECT_NE(collector.GetExtraInfo().find("bindingId:0000002a"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetContextId_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetContextId(12345);
    EXPECT_NE(collector.GetExtraInfo().find("contextId:0000000000003039"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetSuccessAuthType_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetSuccessAuthType(2);
    EXPECT_NE(collector.GetExtraInfo().find("successAuthType:2"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetAlgorithmList_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetAlgorithmList({ 1, 2, 3 });
    EXPECT_NE(collector.GetExtraInfo().find("algorithmList:[1, 2, 3]"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetSelectedAlgorithm_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetSelectedAlgorithm(5);
    EXPECT_NE(collector.GetExtraInfo().find("selectedAlgorithm:5"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetEsl_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetEsl(3);
    EXPECT_NE(collector.GetExtraInfo().find("ESL:3"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetProtocolIdList_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetProtocolIdList({ 10, 20 });
    EXPECT_NE(collector.GetExtraInfo().find("protocolIdList:[10, 20]"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetCapabilityList_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetCapabilityList({ 1 });
    EXPECT_NE(collector.GetExtraInfo().find("capabilityList:[1]"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetSelectedProtocolIdList_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetSelectedProtocolIdList({ 10 });
    EXPECT_NE(collector.GetExtraInfo().find("selectedProtocolIdList:[10]"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetSecureProtocolId_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetSecureProtocolId(99);
    EXPECT_NE(collector.GetExtraInfo().find("secureProtocolId:99"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, AddTemplateAuthResult_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.AddTemplateAuthResult(123, ResultCode::SUCCESS);
    EXPECT_NE(collector.GetExtraInfo().find("templateAuthResult:000000000000007b:0"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, AddTemplateAuthResult_002_MultipleResults, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.AddTemplateAuthResult(123, ResultCode::SUCCESS);
    collector.AddTemplateAuthResult(456, ResultCode::FAIL);
    std::string extraInfo = collector.GetExtraInfo();
    EXPECT_NE(extraInfo.find("templateAuthResult:000000000000007b:0,00000000000001c8"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetSuccessTemplateId_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetSuccessTemplateId(456);
    EXPECT_NE(collector.GetExtraInfo().find("successTemplateId:00000000000001c8"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, MultipleSetMethods_AppendExtraInfo, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetAtl(UserAuth::ATL2);
    collector.SetEsl(1);
    const auto extra = collector.GetExtraInfo();
    EXPECT_NE(extra.find("ATL:"), std::string::npos);
    EXPECT_NE(extra.find("ESL:1"), std::string::npos);
    // ATL should appear before ESL since encoding order is fixed
    EXPECT_LT(extra.find("ATL:"), extra.find("ESL:1"));
}

HWTEST_F(InteractionEventCollectorTest, EmptyExtraInfo_Initially, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    EXPECT_TRUE(collector.GetExtraInfo().empty());
}

HWTEST_F(InteractionEventCollectorTest, UpdateMethods_StoreValues, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetHostUserId(100);
    collector.SetConnectionName("conn1");
    collector.SetScheduleId(0xABCD);
    collector.SetTemplateIdList({ 1, 2, 3 });
    collector.SetTriggerReason("test reason");

    EXPECT_TRUE(collector.GetHostUserId().has_value());
    EXPECT_EQ(collector.GetHostUserId().value(), 100);
    EXPECT_TRUE(collector.GetConnectionName().has_value());
    EXPECT_EQ(collector.GetConnectionName().value(), "conn1");
    EXPECT_TRUE(collector.GetScheduleId().has_value());
    EXPECT_EQ(collector.GetScheduleId().value(), 0xABCD);
    EXPECT_TRUE(collector.GetTemplateIdList().has_value());
    EXPECT_EQ(collector.GetTemplateIdList()->size(), 3u);
    EXPECT_TRUE(collector.GetTriggerReason().has_value());
    EXPECT_EQ(collector.GetTriggerReason().value(), "test reason");
}

HWTEST_F(InteractionEventCollectorTest, SetAlgorithmList_Empty, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetAlgorithmList({});
    EXPECT_NE(collector.GetExtraInfo().find("algorithmList:[]"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetContextId_UpdateOverwrites, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetContextId(100);
    collector.SetContextId(200);
    EXPECT_NE(collector.GetExtraInfo().find("contextId:00000000000000c8"), std::string::npos);
    EXPECT_EQ(collector.GetExtraInfo().find("contextId:0000000000000064"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetEsl_UpdateOverwrites, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetEsl(1);
    collector.SetEsl(2);
    EXPECT_NE(collector.GetExtraInfo().find("ESL:2"), std::string::npos);
    EXPECT_EQ(collector.GetExtraInfo().find("ESL:1"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetAlgorithmList_UpdateOverwrites, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetAlgorithmList({ 1, 2 });
    collector.SetAlgorithmList({ 3, 4, 5 });
    EXPECT_NE(collector.GetExtraInfo().find("algorithmList:[3, 4, 5]"), std::string::npos);
    EXPECT_EQ(collector.GetExtraInfo().find("algorithmList:[1, 2]"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, AllFields_EncodedInFixedOrder, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    // Set in reverse order to verify encoding is independent of call order
    collector.SetSuccessTemplateId(999);
    collector.SetSecureProtocolId(88);
    collector.SetAtl(UserAuth::ATL2);
    collector.SetBindingId(42);

    const auto extra = collector.GetExtraInfo();
    // ATL comes before bindingId in the fixed encoding order
    EXPECT_LT(extra.find("ATL:"), extra.find("bindingId:"));
    // bindingId comes before secureProtocolId
    EXPECT_LT(extra.find("bindingId:"), extra.find("secureProtocolId:"));
    // secureProtocolId comes before successTemplateId
    EXPECT_LT(extra.find("secureProtocolId:"), extra.find("successTemplateId:"));
}

HWTEST_F(InteractionEventCollectorTest, NotSetFields_NotInExtraInfo, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetAtl(UserAuth::ATL1);
    // Only ATL should appear, nothing else
    EXPECT_NE(collector.GetExtraInfo().find("ATL:"), std::string::npos);
    EXPECT_EQ(collector.GetExtraInfo().find("bindingId:"), std::string::npos);
    EXPECT_EQ(collector.GetExtraInfo().find("contextId:"), std::string::npos);
    EXPECT_EQ(collector.GetExtraInfo().find("ESL:"), std::string::npos);
}

// ---------- Report() tests ----------

HWTEST_F(InteractionEventCollectorTest, Report_SetsResultAndCallsAdapter, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    InteractionEventCollector collector("test_request");
    collector.SetHostUserId(100);
    collector.SetConnectionName("conn1");

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);

    collector.Report(ResultCode::SUCCESS);

    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS);
}

HWTEST_F(InteractionEventCollectorTest, Report_SetsResultFail, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    InteractionEventCollector collector("test_request");
    collector.SetHostUserId(200);

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);

    collector.Report(ResultCode::FAIL);

    EXPECT_EQ(collector.GetResult(), ResultCode::FAIL);
}

HWTEST_F(InteractionEventCollectorTest, Report_SetsResultGeneralError, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    InteractionEventCollector collector("test_request");

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);

    collector.Report(ResultCode::GENERAL_ERROR);

    EXPECT_EQ(collector.GetResult(), ResultCode::GENERAL_ERROR);
}

HWTEST_F(InteractionEventCollectorTest, Report_EmptyCollector, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    // Bare collector with only requestType, no fields set
    InteractionEventCollector collector("empty_test");

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);

    collector.Report(ResultCode::SUCCESS);

    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS);
    EXPECT_FALSE(collector.GetHostUserId().has_value());
    EXPECT_FALSE(collector.GetCompanionUserId().has_value());
    EXPECT_FALSE(collector.GetConnectionName().has_value());
    EXPECT_FALSE(collector.GetScheduleId().has_value());
}

HWTEST_F(InteractionEventCollectorTest, Report_SecondCallDoesNotOverwriteResult, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    InteractionEventCollector collector("test_request");

    // Idempotent: exactly one terminal event is emitted; the second Report is a no-op.
    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);

    collector.Report(ResultCode::SUCCESS);
    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS);

    collector.Report(ResultCode::FAIL);
    // First terminal result wins; the later Report does not overwrite it.
    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS);
}

HWTEST_F(InteractionEventCollectorTest, Report_FirstTerminalReportWins_SubsequentCallsAreNoOp, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    InteractionEventCollector collector("test_request");
    collector.SetHostUserId(100);
    collector.SetScheduleId(0xABCD);

    // Idempotent Report: the FIRST terminal Report wins. The two later calls must neither
    // emit another HiSysEvent (adapter called exactly once) nor overwrite the result.
    // (Timing audit finding S1: suppresses the disconnect-vs-timeout / surviving-subscription
    // double-report that previously produced a duplicate event + inflated timing.)
    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);

    collector.Report(ResultCode::SUCCESS);
    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS);

    collector.Report(ResultCode::GENERAL_ERROR);           // no-op
    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS); // first result preserved

    collector.Report(ResultCode::TIMEOUT);                 // no-op
    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS); // first result preserved

    // Previously set fields remain intact after the suppressed Reports.
    EXPECT_TRUE(collector.GetHostUserId().has_value());
    EXPECT_EQ(collector.GetHostUserId().value(), 100);
    EXPECT_TRUE(collector.GetScheduleId().has_value());
    EXPECT_EQ(collector.GetScheduleId().value(), 0xABCD);
}

HWTEST_F(InteractionEventCollectorTest, Report_WithAllFieldsSet, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    InteractionEventCollector collector("full_test");
    collector.SetHostUserId(100);
    collector.SetCompanionUserId(200);
    collector.SetConnectionName("conn_full");
    collector.SetScheduleId(0xBEEF);
    collector.SetTriggerReason("auto");
    collector.SetTemplateIdList({ 1, 2, 3 });
    collector.SetAtl(UserAuth::ATL2);
    collector.SetBindingId(42);
    collector.SetContextId(99999);
    collector.SetSuccessAuthType(4);
    collector.SetAlgorithmList({ 10, 20 });
    collector.SetSelectedAlgorithm(10);
    collector.SetEsl(2);
    collector.SetProtocolIdList({ 100 });
    collector.SetCapabilityList({ 200 });
    collector.SetSelectedProtocolIdList({ 300 });
    collector.SetSecureProtocolId(400);
    collector.AddTemplateAuthResult(555, ResultCode::SUCCESS);
    collector.SetSuccessTemplateId(777);

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);

    collector.Report(ResultCode::SUCCESS);

    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS);
    // Verify all fields are still accessible after Report
    EXPECT_TRUE(collector.GetHostUserId().has_value());
    EXPECT_EQ(collector.GetHostUserId().value(), 100);
    EXPECT_TRUE(collector.GetCompanionUserId().has_value());
    EXPECT_EQ(collector.GetCompanionUserId().value(), 200);
    EXPECT_TRUE(collector.GetConnectionName().has_value());
    EXPECT_EQ(collector.GetConnectionName().value(), "conn_full");
    EXPECT_FALSE(collector.GetExtraInfo().empty());
}

// Regression guard for the double-report timing-inflation bug: a delayed second Report
// (e.g. a surviving subscription firing after completion) must NOT re-stamp endMs_ via a
// second Finish() nor emit a duplicate event. TOTAL_TIME/LOCAL_TIME and the timeTrace
// segment stay frozen at their first-Report values. (Timing audit finding S1.)
HWTEST_F(InteractionEventCollectorTest, Report_SecondCallDoesNotInflateTiming, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();
    auto &timeKeeper = mockGuard.GetTimeKeeper();
    timeKeeper.SetSteadyTime(0);

    InteractionEventCollector collector("test_request");
    collector.Start(); // startMs_ = 0
    timeKeeper.AdvanceSteadyTime(10);
    collector.Mark(STAGE_A); // @10
    timeKeeper.AdvanceSteadyTime(20);
    collector.EnterWait(STAGE_B); // wait begins @30
    timeKeeper.AdvanceSteadyTime(40);
    collector.ExitWait(STAGE_B); // wait ends @70, waitMs = 40

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);
    collector.Report(ResultCode::SUCCESS); // Finish @70 -> TOTAL=70, LOCAL=30

    const auto totalAfterFirst = collector.GetTotalTime();
    const auto localAfterFirst = collector.GetLocalTime();
    const auto extraAfterFirst = collector.GetExtraInfo();
    ASSERT_TRUE(totalAfterFirst.has_value());
    ASSERT_TRUE(localAfterFirst.has_value());
    EXPECT_EQ(*totalAfterFirst, 70u);
    EXPECT_EQ(*localAfterFirst, 30u);

    // Advance the clock well past the first Report; the second Report is suppressed.
    constexpr uint64_t INFLATION_DELTA_MS = 500;
    timeKeeper.AdvanceSteadyTime(INFLATION_DELTA_MS);
    collector.Report(ResultCode::GENERAL_ERROR); // no-op (reported_ already true)

    // Timing must NOT be inflated by INFLATION_DELTA_MS (would be 570/530 if re-stamped).
    ASSERT_TRUE(collector.GetTotalTime().has_value());
    ASSERT_TRUE(collector.GetLocalTime().has_value());
    EXPECT_EQ(*collector.GetTotalTime(), *totalAfterFirst);
    EXPECT_EQ(*collector.GetLocalTime(), *localAfterFirst);
    // timeTrace segment (and the whole extraInfo) is unchanged by the second call.
    EXPECT_EQ(collector.GetExtraInfo(), extraAfterFirst);
}

HWTEST_F(InteractionEventCollectorTest, CollectorTiming_PopulatesTotalLocalAndTrace, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();
    auto &timeKeeper = mockGuard.GetTimeKeeper();
    timeKeeper.SetSteadyTime(0);

    InteractionEventCollector collector("test_request");
    collector.Start();                // startMs_ = 0
    collector.EnterWait(STAGE_A);     // wait begins @0
    timeKeeper.AdvanceSteadyTime(30); // +30 wait
    collector.ExitWait(STAGE_B);      // wait ends @30, waitMs = 30
    timeKeeper.AdvanceSteadyTime(20); // +20 local
    collector.Mark(STAGE_C);          // @50

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(1);
    collector.Report(ResultCode::SUCCESS); // Finish @50 -> TOTAL=50, LOCAL=20

    const auto totalOpt = collector.GetTotalTime();
    const auto localOpt = collector.GetLocalTime();
    ASSERT_TRUE(totalOpt.has_value());
    ASSERT_TRUE(localOpt.has_value());
    EXPECT_EQ(*totalOpt, 50u);
    EXPECT_EQ(*localOpt, 20u);
    // TOTAL == LOCAL + the wait interval (30ms).
    EXPECT_EQ(*totalOpt, *localOpt + 30u);

    // timeTrace segment is the id:delta sequence relative to START.
    const auto extra = collector.GetExtraInfo();
    EXPECT_NE(extra.find("timeTrace:1:0,2:30,3:50"), std::string::npos);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
