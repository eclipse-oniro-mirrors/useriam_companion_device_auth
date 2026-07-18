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

HWTEST_F(InteractionEventCollectorTest, SetCallerUserId_001, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetCallerUserId(100);
    EXPECT_NE(collector.GetExtraInfo().find("callerUserId:100"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetCallerUserId_NotInExtraInfoWhenUnset, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetAtl(UserAuth::ATL1);
    // callerUserId must not leak into extraInfo when never set
    EXPECT_EQ(collector.GetExtraInfo().find("callerUserId:"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetCallerUserId_UpdateOverwrites, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    collector.SetCallerUserId(100);
    collector.SetCallerUserId(200);
    EXPECT_NE(collector.GetExtraInfo().find("callerUserId:200"), std::string::npos);
    EXPECT_EQ(collector.GetExtraInfo().find("callerUserId:100"), std::string::npos);
}

HWTEST_F(InteractionEventCollectorTest, SetCallerUserId_EncodedInFixedOrder, TestSize.Level0)
{
    InteractionEventCollector collector("test");
    // Set in reverse order to verify encoding is independent of call order
    collector.SetEsl(1);
    collector.SetCallerUserId(50);
    collector.SetSelectedAlgorithm(5);

    const auto extra = collector.GetExtraInfo();
    // callerUserId is encoded right after selectedAlgorithm and before ESL
    EXPECT_LT(extra.find("selectedAlgorithm:5"), extra.find("callerUserId:50"));
    EXPECT_LT(extra.find("callerUserId:50"), extra.find("ESL:1"));
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

HWTEST_F(InteractionEventCollectorTest, Report_ConsecutiveCallsUpdateResult, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    InteractionEventCollector collector("test_request");

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(2);

    collector.Report(ResultCode::SUCCESS);
    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS);

    collector.Report(ResultCode::FAIL);
    EXPECT_EQ(collector.GetResult(), ResultCode::FAIL);
}

HWTEST_F(InteractionEventCollectorTest, Report_ConsecutiveCallsOverwriteResult, TestSize.Level0)
{
    MockGuard mockGuard;
    auto &mockAdapter = mockGuard.GetEventManagerAdapter();

    InteractionEventCollector collector("test_request");
    collector.SetHostUserId(100);
    collector.SetScheduleId(0xABCD);

    EXPECT_CALL(mockAdapter, ReportInteractionEvent(::testing::_)).Times(3);

    collector.Report(ResultCode::SUCCESS);
    EXPECT_EQ(collector.GetResult(), ResultCode::SUCCESS);

    collector.Report(ResultCode::GENERAL_ERROR);
    EXPECT_EQ(collector.GetResult(), ResultCode::GENERAL_ERROR);

    collector.Report(ResultCode::TIMEOUT);
    EXPECT_EQ(collector.GetResult(), ResultCode::TIMEOUT);

    // Previously set fields remain intact after multiple Report calls
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

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
