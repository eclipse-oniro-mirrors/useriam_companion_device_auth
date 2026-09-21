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

#include <optional>
#include <string>
#include <vector>

#include "module_test_guard.h"
#include "module_test_helpers.h"
#include "singleton_manager.h"

#include "add_companion_message.h"
#include "cross_device_comm_manager.h"
#include "cross_device_common.h"
#include "iam_logger.h"
#include "sync_device_status_message.h"

#define LOG_TAG "CDA_SA_MODULE_TEST"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class AddCompanionModuleTest : public testing::Test {};

// Helper: build and inject a single-round companion request, capture + verify reply
std::optional<RawMsgInfo> CompanionRoundTrip(ModuleTestGuard &guard, const std::string &connName, uint32_t seq,
    MessageType msgType, const Attributes &payload)
{
    auto rawMsg = BuildRequestRawMsg(connName, seq, msgType, payload);
    return guard.InjectRequestAndCaptureReply(connName, rawMsg, msgType);
}

// Helper: verify END_ADD_HOST_BINDING outbound fields
void VerifyEndAddHostBindingFields(const RawMsgInfo &msg, UserId hostUserId,
    const std::vector<uint8_t> &expectedTokenData)
{
    int32_t v = 0;
    EXPECT_TRUE(msg.payload.GetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, v));
    EXPECT_EQ(v, hostUserId);
    EXPECT_TRUE(msg.payload.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, v));
    EXPECT_EQ(v, hostUserId);
    EXPECT_TRUE(msg.payload.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, v));
    EXPECT_EQ(static_cast<ResultCode>(v), ResultCode::SUCCESS);
    std::vector<uint8_t> extraInfo;
    EXPECT_TRUE(msg.payload.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, extraInfo));
    EXPECT_EQ(extraInfo, expectedTokenData);
}

// Helper: Setup all three host-side SecurityAgent mocks for full AddCompanion flow
void SetupHostAddCompanionMocks(ModuleTestGuard &guard, const HostGetInitKeyNegotiationRequestOutput &initOutput,
    const HostBeginAddCompanionOutput &beginOutput, const HostEndAddCompanionOutput &endOutput)
{
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(initOutput), Return(ResultCode::SUCCESS)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginAddCompanion(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndAddCompanion(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(endOutput), Return(ResultCode::SUCCESS)));
}

// Parameters for BuildAndInjectReply
struct ReplyParams {
    MessageType msgType;
    ResultCode result = ResultCode::GENERAL_ERROR;
    std::vector<uint8_t> extraInfo;
};

// Helper: build + encode + inject reply for a captured outbound message
void BuildAndInjectReply(ModuleTestGuard &guard, const std::string &connName, const RawMsgInfo &captured,
    const ReplyParams &params)
{
    Attributes payload;
    if (params.msgType == MessageType::INIT_KEY_NEGOTIATION) {
        InitKeyNegotiationReply r;
        r.result = params.result;
        r.extraInfo = params.extraInfo;
        EncodeInitKeyNegotiationReply(r, payload);
    } else if (params.msgType == MessageType::BEGIN_ADD_HOST_BINDING) {
        BeginAddHostBindingReply r;
        r.result = params.result;
        r.extraInfo = params.extraInfo;
        EncodeBeginAddHostBindingReply(r, payload);
    } else {
        EndAddHostBindingReply r;
        r.result = params.result;
        EncodeEndAddHostBindingReply(r, payload);
    }
    guard.InjectTypedReply(connName, captured.seq, params.msgType, payload);
}

// Helper: Capture outbound message and inject reply in one call
void CaptureAndReply(ModuleTestGuard &guard, const std::string &connName, MessageType msgType,
    const ReplyParams &params)
{
    auto captured = guard.CaptureOutboundMessage(connName, msgType);
    ASSERT_TRUE(captured.has_value());
    EXPECT_FALSE(captured->isReply); // Host outbound messages should not be replies
    BuildAndInjectReply(guard, connName, *captured, params);
}

// Helper: Capture, verify fields, and inject reply (for Round 2 with BEGIN_ADD_HOST_BINDING)
void CaptureVerifyBeginAndReply(ModuleTestGuard &guard, const std::string &connName, UserId expectedUserId,
    const std::vector<uint8_t> &expectedExtraInfo, const ReplyParams &params)
{
    auto captured = guard.CaptureOutboundMessage(connName, MessageType::BEGIN_ADD_HOST_BINDING);
    ASSERT_TRUE(captured.has_value());
    auto beginReq = DecodeBeginAddHostBindingRequest(captured->payload);
    ASSERT_TRUE(beginReq.has_value());
    EXPECT_EQ(beginReq->companionUserKey.userId, expectedUserId);
    EXPECT_EQ(beginReq->extraInfo, expectedExtraInfo);
    BuildAndInjectReply(guard, connName, *captured, params);
}

// Helper: Capture, verify END_ADD_HOST_BINDING fields, and inject reply
void CaptureVerifyEndAndReply(ModuleTestGuard &guard, const std::string &connName, UserId hostUserId,
    const std::vector<uint8_t> &expectedTokenData, const ReplyParams &params)
{
    auto captured = guard.CaptureOutboundMessage(connName, MessageType::END_ADD_HOST_BINDING);
    ASSERT_TRUE(captured.has_value());
    VerifyEndAddHostBindingFields(*captured, hostUserId, expectedTokenData);
    BuildAndInjectReply(guard, connName, *captured, params);
}

// Helper: build a companion-side request payload for message flow
Attributes BuildInitKeyNegotiationPayload(const std::string &hostDeviceId, UserId hostUserId,
    const std::vector<uint8_t> &extraInfo)
{
    InitKeyNegotiationRequest req;
    req.hostDeviceKey = MakeDeviceKey(hostDeviceId, hostUserId);
    req.extraInfo = extraInfo;
    Attributes payload;
    EncodeInitKeyNegotiationRequest(req, payload);
    return payload;
}

Attributes BuildBeginAddHostBindingPayload(UserId companionUserId, const std::vector<uint8_t> &extraInfo)
{
    BeginAddHostBindingRequest req;
    req.companionUserKey.userId = companionUserId;
    req.extraInfo = extraInfo;
    Attributes payload;
    EncodeBeginAddHostBindingRequest(req, payload);
    return payload;
}

Attributes BuildEndAddHostBindingPayload(const std::string &hostDeviceId, UserId hostUserId, UserId companionUserId,
    ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    EndAddHostBindingRequest req;
    req.hostDeviceKey = MakeDeviceKey(hostDeviceId, hostUserId);
    req.companionUserKey.userId = companionUserId;
    req.result = result;
    req.extraInfo = extraInfo;
    Attributes payload;
    EncodeEndAddHostBindingRequest(req, payload);
    return payload;
}

// ============================================================================
// Test 1: CompanionAddCompanionInitKeyNegotiationE2E_001
// ============================================================================
HWTEST_F(AddCompanionModuleTest, CompanionAddCompanionInitKeyNegotiationE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    const std::string connName = "test-conn-add-001";

    // Setup Mock: CompanionInitKeyNegotiation returns algorithm list + reply
    CompanionInitKeyNegotiationOutput initOutput;
    initOutput.initKeyNegotiationReply = { 0x11, 0x22, 0x33, 0x44 };
    initOutput.algorithmList = { 1, 2, 3 };
    initOutput.selectedAlgorithm = 2;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(initOutput), Return(ResultCode::SUCCESS)));

    // Create inbound connection + build request
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-test-device-001"));
    DrainPendingTasks();

    InitKeyNegotiationRequest request;
    request.hostDeviceKey = MakeDeviceKey("host-test-device-001", 200);
    request.extraInfo = { 0xAA, 0xBB, 0xCC };
    Attributes requestPayload;
    EncodeInitKeyNegotiationRequest(request, requestPayload);

    // Inject and capture reply
    auto replyInfo = CompanionRoundTrip(guard, connName, 1, MessageType::INIT_KEY_NEGOTIATION, requestPayload);
    ASSERT_TRUE(replyInfo.has_value()) << "Expected InitKeyNegotiationReply";
    EXPECT_EQ(replyInfo->seq, 1u);
    EXPECT_TRUE(replyInfo->isReply);
    EXPECT_EQ(replyInfo->msgType, MessageType::INIT_KEY_NEGOTIATION);

    auto replyOpt = DecodeInitKeyNegotiationReply(replyInfo->payload);
    ASSERT_TRUE(replyOpt.has_value()) << "Failed to decode InitKeyNegotiationReply";
    EXPECT_EQ(replyOpt->result, ResultCode::SUCCESS);
    EXPECT_EQ(replyOpt->extraInfo, initOutput.initKeyNegotiationReply);
}

// ============================================================================
// Test 2: CompanionAddCompanionFullE2E_001 — Full 3-round companion flow
// ============================================================================
HWTEST_F(AddCompanionModuleTest, CompanionAddCompanionFullE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    const std::string connName = "test-conn-add-full-001";
    constexpr UserId COMPANION_USER_ID = 100;
    constexpr UserId HOST_USER_ID = 200;
    const std::string hostDeviceId = "host-test-device-full-001";

    CompanionInitKeyNegotiationOutput initOutput;
    initOutput.initKeyNegotiationReply = { 0x11, 0x22, 0x33, 0x44 };
    initOutput.algorithmList = { 1, 2 };
    initOutput.selectedAlgorithm = 1;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(initOutput), Return(ResultCode::SUCCESS)));

    CompanionBeginAddHostBindingOutput beginOutput;
    beginOutput.addHostBindingReply = { 0x44, 0x55 };
    beginOutput.replacedBindingId = std::nullopt;
    beginOutput.hostBindingStatus.bindingId = 42;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginAddHostBinding(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    CompanionEndAddHostBindingOutput endOutput;
    endOutput.atl = 2;
    endOutput.esl = 1;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndAddHostBinding(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(endOutput), Return(ResultCode::SUCCESS)));

    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey(hostDeviceId));
    DrainPendingTasks();

    // Round 1: INIT_KEY_NEGOTIATION
    auto r1 = CompanionRoundTrip(guard, connName, 1, MessageType::INIT_KEY_NEGOTIATION,
        BuildInitKeyNegotiationPayload(hostDeviceId, HOST_USER_ID, { 0xAA, 0xBB }));
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->seq, 1u);
    auto initReply = DecodeInitKeyNegotiationReply(r1->payload);
    ASSERT_TRUE(initReply.has_value());
    EXPECT_EQ(initReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(initReply->extraInfo, initOutput.initKeyNegotiationReply);

    // Round 2: BEGIN_ADD_HOST_BINDING
    auto r2 = CompanionRoundTrip(guard, connName, 2, MessageType::BEGIN_ADD_HOST_BINDING,
        BuildBeginAddHostBindingPayload(COMPANION_USER_ID, { 0xCC, 0xDD }));
    ASSERT_TRUE(r2.has_value());
    auto beginReply = DecodeBeginAddHostBindingReply(r2->payload);
    ASSERT_TRUE(beginReply.has_value());
    EXPECT_EQ(beginReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(beginReply->extraInfo, beginOutput.addHostBindingReply);

    // Round 3: END_ADD_HOST_BINDING
    auto r3 = CompanionRoundTrip(guard, connName, 3, MessageType::END_ADD_HOST_BINDING,
        BuildEndAddHostBindingPayload(hostDeviceId, HOST_USER_ID, COMPANION_USER_ID, ResultCode::SUCCESS,
            { 0xEE, 0xFF }));
    ASSERT_TRUE(r3.has_value());
    auto endReply = DecodeEndAddHostBindingReply(r3->payload);
    ASSERT_TRUE(endReply.has_value());
    EXPECT_EQ(endReply->result, ResultCode::SUCCESS);
}

// ============================================================================
// Test 3: CompanionDuplicateAddReplacedBindingE2E_001
// ============================================================================
HWTEST_F(AddCompanionModuleTest, CompanionDuplicateAddReplacedBindingE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    const std::string connName = "test-conn-replace-001";
    constexpr UserId COMPANION_USER_ID = 100;
    constexpr UserId HOST_USER_ID = 200;
    constexpr BindingId EXISTING_BINDING_ID = 999;
    const std::string hostDeviceId = "host-test-device-replace-001";

    CompanionInitKeyNegotiationOutput initOutput;
    initOutput.initKeyNegotiationReply = { 0x11, 0x22 };
    initOutput.algorithmList = { 1 };
    initOutput.selectedAlgorithm = 1;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(initOutput), Return(ResultCode::SUCCESS)));

    CompanionBeginAddHostBindingOutput beginOutput;
    beginOutput.addHostBindingReply = { 0x55, 0x66 };
    beginOutput.replacedBindingId = EXISTING_BINDING_ID;
    beginOutput.hostBindingStatus.bindingId = 43;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginAddHostBinding(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    CompanionEndAddHostBindingOutput endOutput;
    endOutput.atl = 1;
    endOutput.esl = 0;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndAddHostBinding(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(endOutput), Return(ResultCode::SUCCESS)));

    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey(hostDeviceId));
    DrainPendingTasks();

    // Round 1: INIT_KEY_NEGOTIATION
    auto r1 = CompanionRoundTrip(guard, connName, 1, MessageType::INIT_KEY_NEGOTIATION,
        BuildInitKeyNegotiationPayload(hostDeviceId, HOST_USER_ID, { 0xAA }));
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->seq, 1u);

    // Round 2: BEGIN_ADD_HOST_BINDING (replacedBindingId verified via mock)
    auto r2 = CompanionRoundTrip(guard, connName, 2, MessageType::BEGIN_ADD_HOST_BINDING,
        BuildBeginAddHostBindingPayload(COMPANION_USER_ID, { 0xBB }));
    ASSERT_TRUE(r2.has_value());
    auto beginReply = DecodeBeginAddHostBindingReply(r2->payload);
    ASSERT_TRUE(beginReply.has_value());
    EXPECT_EQ(beginReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(beginReply->extraInfo, beginOutput.addHostBindingReply);

    // Round 3: END_ADD_HOST_BINDING
    auto r3 = CompanionRoundTrip(guard, connName, 3, MessageType::END_ADD_HOST_BINDING,
        BuildEndAddHostBindingPayload(hostDeviceId, HOST_USER_ID, COMPANION_USER_ID, ResultCode::SUCCESS, { 0xCC }));
    ASSERT_TRUE(r3.has_value());
    auto endReply = DecodeEndAddHostBindingReply(r3->payload);
    ASSERT_TRUE(endReply.has_value());
    EXPECT_EQ(endReply->result, ResultCode::SUCCESS);
}

// ============================================================================
// Test 4: CompanionAddCompanionInitKeyNegotiationErrorE2E_001
// ============================================================================
HWTEST_F(AddCompanionModuleTest, CompanionAddCompanionInitKeyNegotiationErrorE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    const std::string connName = "test-conn-error-001";

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-test-device-error-001"));
    DrainPendingTasks();

    InitKeyNegotiationRequest request;
    request.hostDeviceKey = MakeDeviceKey("host-test-device-error-001", 200);
    request.extraInfo = { 0xAA };
    Attributes requestPayload;
    EncodeInitKeyNegotiationRequest(request, requestPayload);

    auto replyInfo = CompanionRoundTrip(guard, connName, 1, MessageType::INIT_KEY_NEGOTIATION, requestPayload);
    ASSERT_TRUE(replyInfo.has_value());
    EXPECT_EQ(replyInfo->seq, 1u);
    EXPECT_TRUE(replyInfo->isReply);

    int32_t result = 0;
    ASSERT_TRUE(replyInfo->payload.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

// ============================================================================
// Test 5: HostAddCompanionFullE2E_001 — Full 3-round host flow
// ============================================================================
HWTEST_F(AddCompanionModuleTest, HostAddCompanionFullE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr UserId HOST_USER_ID = 100;
    const std::string deviceId = "companion-test-device-host-001";

    guard.SetupHostSideSync(deviceId, HOST_USER_ID);

    // Setup all three SecurityAgent mocks
    HostGetInitKeyNegotiationRequestOutput initReqOutput = { { 0x01, 0x02, 0x03 }, { 1, 2 } };
    HostBeginAddCompanionOutput beginCompOutput;
    beginCompOutput.addHostBindingRequest = { 0x04, 0x05, 0x06 };
    beginCompOutput.selectedAlgorithm = 1;
    HostEndAddCompanionOutput endCompOutput = { .fwkMsg = { 0x07, 0x08 },
        .templateId = 12345,
        .tokenData = { 0x09, 0x0A },
        .atl = 3,
        .esl = 1 };
    SetupHostAddCompanionMocks(guard, initReqOutput, beginCompOutput, endCompOutput);

    // Enroll and get connection
    FwkCallbackCapture cbCapture;
    ASSERT_TRUE(guard.Enroll(1001, { 0xAA, 0xBB }, 999, R"({"enabled_business_ids":[1,2]})", cbCapture.MakeCallback()));
    DrainPendingTasks();
    guard.GetMiscManager().TestSimulateDeviceSelectResult(999, { MakeDeviceKey(deviceId, HOST_USER_ID) });
    DrainPendingTasks();
    std::string connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());

    // Round 1: INIT_KEY_NEGOTIATION
    CaptureAndReply(guard, connName, MessageType::INIT_KEY_NEGOTIATION,
        { MessageType::INIT_KEY_NEGOTIATION, ResultCode::SUCCESS, { 0xCC, 0xDD } });

    // Round 2: BEGIN_ADD_HOST_BINDING (verify request fields)
    CaptureVerifyBeginAndReply(guard, connName, HOST_USER_ID, beginCompOutput.addHostBindingRequest,
        { MessageType::BEGIN_ADD_HOST_BINDING, ResultCode::SUCCESS, { 0xEE, 0xFF } });

    // Round 3: END_ADD_HOST_BINDING (verify request fields)
    CaptureVerifyEndAndReply(guard, connName, HOST_USER_ID, endCompOutput.tokenData,
        { MessageType::END_ADD_HOST_BINDING, ResultCode::SUCCESS });

    // Verify callback + companion persistence
    EXPECT_TRUE(cbCapture.invoked);
    EXPECT_EQ(cbCapture.result, ResultCode::SUCCESS);
    EXPECT_EQ(cbCapture.extraInfo, endCompOutput.fwkMsg);
    guard.GetIdmAdapter().TestSimulateTemplateChange(HOST_USER_ID, { endCompOutput.templateId });
    DrainPendingTasks();
    ASSERT_TRUE(
        GetCompanionManager().GetCompanionStatus(
            UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID }, MakeDeviceKey(deviceId, HOST_USER_ID)).has_value());
}

// ============================================================================
// Test 6: HostAddCompanionBeginAddCompanionFailedE2E_006
// ============================================================================
HWTEST_F(AddCompanionModuleTest, HostAddCompanionBeginAddCompanionFailedE2E_006, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr UserId HOST_USER_ID = 100;
    constexpr ScheduleId TEST_SCHEDULE_ID = 1002;
    constexpr uint32_t testTokenId = 998;
    const std::string deviceId = "companion-test-device-begin-err-001";
    const std::string testAdditionalInfo = R"({"enabled_business_ids":[1,2]})";

    guard.SetupHostSideSync(deviceId, HOST_USER_ID);

    HostGetInitKeyNegotiationRequestOutput initReqOutput;
    initReqOutput.initKeyNegotiationRequest = { 0x01, 0x02, 0x03 };
    initReqOutput.algorithmList = { 1, 2 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(initReqOutput), Return(ResultCode::SUCCESS)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginAddCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    FwkCallbackCapture cbCapture;
    ASSERT_TRUE(
        guard.Enroll(TEST_SCHEDULE_ID, { 0xAA, 0xBB }, testTokenId, testAdditionalInfo, cbCapture.MakeCallback()));
    DrainPendingTasks();
    guard.GetMiscManager().TestSimulateDeviceSelectResult(testTokenId, { MakeDeviceKey(deviceId, HOST_USER_ID) });
    DrainPendingTasks();

    std::string connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());

    // Round 1: INIT_KEY_NEGOTIATION — inject reply
    InitKeyNegotiationReply initReply;
    initReply.result = ResultCode::SUCCESS;
    initReply.extraInfo = { 0xCC, 0xDD };
    Attributes initReplyPayload;
    EncodeInitKeyNegotiationReply(initReply, initReplyPayload);
    ASSERT_TRUE(guard.CaptureVerifyAndReply(connName, MessageType::INIT_KEY_NEGOTIATION, initReplyPayload));

    // HostBeginAddCompanion fails → callback with error
    EXPECT_TRUE(cbCapture.invoked);
    EXPECT_EQ(cbCapture.result, ResultCode::GENERAL_ERROR);
    EXPECT_FALSE(
        GetCompanionManager().GetCompanionStatus(
            UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID }, MakeDeviceKey(deviceId, HOST_USER_ID)).has_value());
}

// ============================================================================
// Test 7: HostAddCompanionEndAddCompanionFailedE2E_007
// ============================================================================
HWTEST_F(AddCompanionModuleTest, HostAddCompanionEndAddCompanionFailedE2E_007, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr UserId HOST_USER_ID = 100;
    constexpr ScheduleId TEST_SCHEDULE_ID = 1003;
    constexpr uint32_t testTokenId = 997;
    const std::string deviceId = "companion-test-device-end-err-001";
    const std::string testAdditionalInfo = R"({"enabled_business_ids":[1,2]})";

    guard.SetupHostSideSync(deviceId, HOST_USER_ID);

    HostGetInitKeyNegotiationRequestOutput initReqOutput;
    initReqOutput.initKeyNegotiationRequest = { 0x01, 0x02, 0x03 };
    initReqOutput.algorithmList = { 1, 2 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(initReqOutput), Return(ResultCode::SUCCESS)));

    HostBeginAddCompanionOutput beginCompOutput;
    beginCompOutput.addHostBindingRequest = { 0x04, 0x05, 0x06 };
    beginCompOutput.selectedAlgorithm = 1;
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginAddCompanion(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginCompOutput), Return(ResultCode::SUCCESS)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndAddCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    FwkCallbackCapture cbCapture;
    ASSERT_TRUE(
        guard.Enroll(TEST_SCHEDULE_ID, { 0xAA, 0xBB }, testTokenId, testAdditionalInfo, cbCapture.MakeCallback()));
    DrainPendingTasks();
    guard.GetMiscManager().TestSimulateDeviceSelectResult(testTokenId, { MakeDeviceKey(deviceId, HOST_USER_ID) });
    DrainPendingTasks();

    std::string connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());

    // Round 1: INIT_KEY_NEGOTIATION
    InitKeyNegotiationReply initReply;
    initReply.result = ResultCode::SUCCESS;
    initReply.extraInfo = { 0xCC, 0xDD };
    Attributes initReplyPayload;
    EncodeInitKeyNegotiationReply(initReply, initReplyPayload);
    ASSERT_TRUE(guard.CaptureVerifyAndReply(connName, MessageType::INIT_KEY_NEGOTIATION, initReplyPayload));

    // Round 2: BEGIN_ADD_HOST_BINDING
    BeginAddHostBindingReply beginReply;
    beginReply.result = ResultCode::SUCCESS;
    beginReply.extraInfo = { 0xEE, 0xFF };
    Attributes beginReplyPayload;
    EncodeBeginAddHostBindingReply(beginReply, beginReplyPayload);
    ASSERT_TRUE(guard.CaptureVerifyAndReply(connName, MessageType::BEGIN_ADD_HOST_BINDING, beginReplyPayload));

    // HostEndAddCompanion fails → callback with error
    EXPECT_TRUE(cbCapture.invoked);
    EXPECT_EQ(cbCapture.result, ResultCode::GENERAL_ERROR);
    EXPECT_FALSE(
        GetCompanionManager().GetCompanionStatus(
            UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID }, MakeDeviceKey(deviceId, HOST_USER_ID)).has_value());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
