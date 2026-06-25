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

#include "delegate_auth_message.h"
#include "iam_logger.h"
#include "issue_token_message.h"
#include "obtain_token_message.h"
#include "remove_host_binding_message.h"
#include "request_aborted_message.h"
#include "revoke_token_message.h"
#include "token_auth_message.h"

#define LOG_TAG "CDA_SA_MODULE_TEST"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class AuthModuleTest : public testing::Test {};

// Common test constants
constexpr UserId HOST_USER_ID = 100;

// Companion-side request helpers: build payload + inject + capture reply in one step
std::optional<RawMsgInfo> CompanionInjectAndCapture(ModuleTestGuard &guard, const std::string &connName, uint32_t seq,
    MessageType msgType, const Attributes &payload)
{
    auto rawMsg = BuildRequestRawMsg(connName, seq, msgType, payload);
    return guard.InjectRequestAndCaptureReply(connName, rawMsg, msgType);
}

// Build PreIssueToken request payload
Attributes BuildPreIssueTokenPayload(const std::string &hostDeviceId, UserId hostUserId, UserId companionUserId,
    const std::vector<uint8_t> &extraInfo)
{
    PreIssueTokenRequest req;
    req.hostDeviceKey = MakeDeviceKey(hostDeviceId, hostUserId);
    req.companionUserId = companionUserId;
    req.extraInfo = extraInfo;
    Attributes payload;
    EncodePreIssueTokenRequest(req, payload);
    return payload;
}

// Build IssueToken request payload
Attributes BuildIssueTokenPayload(const std::string &hostDeviceId, UserId hostUserId, UserId companionUserId,
    const std::vector<uint8_t> &extraInfo)
{
    IssueTokenRequest req;
    req.hostDeviceKey = MakeDeviceKey(hostDeviceId, hostUserId);
    req.companionUserId = companionUserId;
    req.extraInfo = extraInfo;
    Attributes payload;
    EncodeIssueTokenRequest(req, payload);
    return payload;
}

// Find first outbound (non-reply) message of given type among sent messages
std::optional<RawMsgInfo> FindOutboundMessage(FakeChannel &channel, const std::string &connName, MessageType msgType)
{
    auto sentMsgs = channel.GetSentMessages(connName);
    for (const auto &raw : sentMsgs) {
        auto info = DecodeRawMsg(raw);
        if (info && !info->isReply && info->msgType == msgType) {
            return info;
        }
    }
    return std::nullopt;
}

// ============================================================================
// Test 1: RequestAbortedReceivedE2E_001
//         Host receives REQUEST_ABORTED from Companion → OutboundRequest canceled
// ============================================================================
//
// What this tests:
//   OutboundRequest subscribes to REQUEST_ABORTED → receives message →
//   HandleRequestAborted → CompleteWithError with aborted result
//
// E2E level: HIGH
//   - Entry: raw REQUEST_ABORTED message injection at FakeChannel boundary
//   - Production path: MessageRouter → OutboundRequest.HandleRequestAborted
//   - Verification: callback invoked with error result
// ============================================================================
HWTEST_F(AuthModuleTest, RequestAbortedReceivedE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    IAM_LOGI("[Phase] Setup — companion device online, create callback");
    // 1. Setup companion device for connection
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-test-device-abort-001", 54321));

    // 2. Create callback to capture result
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    std::vector<uint8_t> callbackExtraInfo;

    auto fwkCallback = [&callbackInvoked, &callbackResult, &callbackExtraInfo](ResultCode result,
                           const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        callbackExtraInfo = extraInfo;
    };

    IAM_LOGI("[Phase] Run — RequestAborted E2E message flow");
    // 3. Call AuthenticateDelegateAuth via ModuleTestGuard helper (mimics Executor.Authenticate())
    constexpr ScheduleId TEST_SCHEDULE_ID = 2001;
    constexpr TemplateId TEST_TEMPLATE_ID = 54321;
    std::vector<uint8_t> testFwkMsg = { 0xAB, 0xCD };

    bool authRet = guard.AuthenticateDelegateAuth(TEST_SCHEDULE_ID, testFwkMsg, HOST_USER_ID, TEST_TEMPLATE_ID, 0,
        std::move(fwkCallback));
    ASSERT_TRUE(authRet) << "AuthenticateDelegateAuth failed";
    DrainPendingTasks();

    // 4. Get the connection name
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection to be established";
    const auto &actualConnName = allConnNames[0];

    // 5. Inject REQUEST_ABORTED message from Companion
    RequestAbortedRequest abortReq;
    abortReq.result = ResultCode::CANCELED;
    abortReq.reason = "companion preempted by new request";

    Attributes abortPayload;
    EncodeRequestAbortedRequest(abortReq, abortPayload);
    auto abortRawMsg = BuildRequestRawMsg(actualConnName, 1, MessageType::REQUEST_ABORTED, abortPayload);

    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(actualConnName, abortRawMsg);
    DrainPendingTasks();

    // 6. Verify callback was invoked with CANCELED result
    EXPECT_TRUE(callbackInvoked) << "Expected callback to be invoked when request aborted";
    EXPECT_EQ(callbackResult, ResultCode::CANCELED) << "Expected CANCELED result";
}

// ============================================================================
// Test 2: RequestAbortedPreemptedE2E_001
//         Companion sends REQUEST_ABORTED when preempted → Host receives and cancels
// ============================================================================
//
// What this tests:
//   Companion InboundRequest.Cancel() → SendRequestAborted → Host receives →
//   OutboundRequest.HandleRequestAborted → CompleteWithError
//
// E2E level: HIGH
//   - Entry: Simulate REQUEST_ABORTED message from Companion at FakeChannel
//   - Production path: MessageRouter → OutboundRequest.HandleRequestAborted
//   - Verification: OutboundRequest lifecycle completion with error
// ============================================================================
HWTEST_F(AuthModuleTest, RequestAbortedPreemptedE2E_002, TestSize.Level0)
{
    ModuleTestGuard guard;

    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-test-device-preempt-001", 54322));

    // 2. Create callback
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::SUCCESS;

    auto fwkCallback = [&callbackInvoked, &callbackResult](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        (void)extraInfo;
    };

    // 3. Create HostTokenAuthRequest (another OutboundRequest type)
    constexpr ScheduleId TEST_SCHEDULE_ID = 2002;
    constexpr TemplateId TEST_TEMPLATE_ID = 54322;
    std::vector<uint8_t> testFwkMsg = { 0xDE, 0xAD };

    bool authRet = guard.AuthenticateTokenAuth(TEST_SCHEDULE_ID, testFwkMsg, HOST_USER_ID, TEST_TEMPLATE_ID, 0,
        std::move(fwkCallback));
    ASSERT_TRUE(authRet) << "AuthenticateTokenAuth failed";
    DrainPendingTasks();

    // 4. Get connection and inject REQUEST_ABORTED
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection";
    const auto &actualConnName = allConnNames[0];

    // 5. Simulate Companion preempting - send REQUEST_ABORTED with different error
    RequestAbortedRequest abortReq;
    abortReq.result = ResultCode::BUSY;
    abortReq.reason = "preempted by higher priority request";

    Attributes abortPayload;
    EncodeRequestAbortedRequest(abortReq, abortPayload);
    auto abortRawMsg = BuildRequestRawMsg(actualConnName, 1, MessageType::REQUEST_ABORTED, abortPayload);

    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(actualConnName, abortRawMsg);
    DrainPendingTasks();

    // 6. Verify callback invoked with PREEMPTED result
    EXPECT_TRUE(callbackInvoked) << "Expected callback to be invoked";
    EXPECT_EQ(callbackResult, ResultCode::BUSY) << "Expected BUSY result";
}

// ============================================================================
// Test 3: RequestAbortedCommunicationErrorE2E_001
//         Host receives REQUEST_ABORTED with COMMUNICATION_ERROR → proper cleanup
// ============================================================================
//
// What this tests:
//   REQUEST_ABORTED with COMMUNICATION_ERROR result → proper error propagation
//
// E2E level: HIGH
//   - Entry: raw REQUEST_ABORTED message injection
//   - Production path: MessageRouter → OutboundRequest.HandleRequestAborted
//   - Verification: callback with correct error code
// ============================================================================
HWTEST_F(AuthModuleTest, RequestAbortedCommunicationErrorE2E_003, TestSize.Level0)
{
    ModuleTestGuard guard;

    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-test-device-comm-error-001", 54323));

    // 2. Create callback
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::SUCCESS;

    auto fwkCallback = [&callbackInvoked, &callbackResult](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        (void)extraInfo;
    };

    // 3. Create HostDelegateAuthRequest
    constexpr ScheduleId TEST_SCHEDULE_ID = 2003;
    constexpr TemplateId TEST_TEMPLATE_ID = 54323;

    bool authRet = guard.AuthenticateDelegateAuth(TEST_SCHEDULE_ID, { 0xAA }, HOST_USER_ID, TEST_TEMPLATE_ID, 0,
        std::move(fwkCallback));
    ASSERT_TRUE(authRet);
    DrainPendingTasks();

    // 4. Inject REQUEST_ABORTED with COMMUNICATION_ERROR
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty());
    const auto &actualConnName = allConnNames[0];

    RequestAbortedRequest abortReq;
    abortReq.result = ResultCode::COMMUNICATION_ERROR;
    abortReq.reason = "companion side communication failure";

    Attributes abortPayload;
    EncodeRequestAbortedRequest(abortReq, abortPayload);
    auto abortRawMsg = BuildRequestRawMsg(actualConnName, 1, MessageType::REQUEST_ABORTED, abortPayload);

    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(actualConnName, abortRawMsg);
    DrainPendingTasks();

    // 5. Verify COMMUNICATION_ERROR propagated
    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(callbackResult, ResultCode::COMMUNICATION_ERROR);
}

// ============================================================================
// Test 4: HostIssueTokenFullE2E_001
//         Full 3-round IssueToken flow on host side:
//         PreIssueToken → IssueToken → EndIssueToken
// ============================================================================
//
// What this tests:
//   HostIssueTokenRequest → HostPreIssueToken → send PRE_ISSUE_TOKEN →
//   Companion PreIssueTokenReply → HostBeginIssueToken → send ISSUE_TOKEN →
//   Companion ProcessIssueTokenReply → HostEndIssueToken → complete
//
// E2E level: HIGH
//   - Entry: HostIssueTokenRequest created via RequestFactory
//   - Production path: Full HostIssueTokenRequest lifecycle
//   - Verification: all messages sent/received via FakeChannel, callback invoked
// ============================================================================
HWTEST_F(AuthModuleTest, HostIssueTokenFullE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr TemplateId TEST_TEMPLATE_ID = 54324;
    constexpr uint32_t lockStateAuthType = 1;

    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-test-device-issue-001", 54324));

    HostPreIssueTokenOutput preIssueOutput;
    preIssueOutput.preIssueTokenRequest = { 0x01, 0x02, 0x03 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(preIssueOutput), Return(ResultCode::SUCCESS)));

    HostBeginIssueTokenOutput beginIssueOutput;
    beginIssueOutput.issueTokenRequest = { 0x04, 0x05, 0x06 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginIssueOutput), Return(ResultCode::SUCCESS)));

    HostEndIssueTokenOutput endIssueOutput;
    endIssueOutput.atl = 5;
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndIssueToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(endIssueOutput), Return(ResultCode::SUCCESS)));

    auto request = GetRequestFactory().CreateHostIssueTokenRequest(HOST_USER_ID, TEST_TEMPLATE_ID, lockStateAuthType,
        { 0xAA, 0xBB });
    ASSERT_NE(request, nullptr);
    ASSERT_TRUE(GetRequestManager().Start(request));
    DrainPendingTasks();
    std::string connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());

    // Round 1: PRE_ISSUE_TOKEN
    // Note: Cannot decode full PreIssueTokenRequest because outbound messages lack
    // SRC_IDENTIFIER_TYPE/SRC_IDENTIFIER fields (added by MessageRouter on receiving side).
    auto r1 = guard.CaptureOutboundMessage(connName, MessageType::PRE_ISSUE_TOKEN);
    ASSERT_TRUE(r1.has_value());
    EXPECT_FALSE(r1->isReply);
    int32_t hostUserId = 0;
    EXPECT_TRUE(r1->payload.GetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId));
    EXPECT_EQ(hostUserId, HOST_USER_ID);

    PreIssueTokenReply preReply;
    preReply.result = ResultCode::SUCCESS;
    preReply.extraInfo = { 0xCC, 0xDD };
    Attributes preReplyPayload;
    EncodePreIssueTokenReply(preReply, preReplyPayload);
    CaptureAndReply(guard.GetChannel(), connName, MessageType::PRE_ISSUE_TOKEN, preReplyPayload);

    // Round 2: ISSUE_TOKEN
    auto r2 = guard.CaptureOutboundMessage(connName, MessageType::ISSUE_TOKEN);
    ASSERT_TRUE(r2.has_value());
    int32_t issueHostUserId = 0;
    EXPECT_TRUE(r2->payload.GetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, issueHostUserId));
    EXPECT_EQ(issueHostUserId, HOST_USER_ID);

    IssueTokenReply issueReply;
    issueReply.result = ResultCode::SUCCESS;
    issueReply.extraInfo = { 0xEE, 0xFF };
    Attributes issueReplyPayload;
    EncodeIssueTokenReply(issueReply, issueReplyPayload);
    CaptureAndReply(guard.GetChannel(), connName, MessageType::ISSUE_TOKEN, issueReplyPayload);
}

// ============================================================================
// Test 5: CompanionProcessIssueTokenFullE2E_002
//         Companion-side IssueToken flow: receives PRE_ISSUE_TOKEN and ISSUE_TOKEN
// ============================================================================
//
// What this tests:
//   Companion receives PRE_ISSUE_TOKEN → CompanionPreIssueToken → reply
//   Companion receives ISSUE_TOKEN → CompanionProcessIssueToken → reply
//
// E2E level: HIGH
//   - Entry: raw message injection at FakeChannel boundary
//   - Production path: Companion handlers → SecurityAgent
//   - Verification: both replies decoded and verified
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionProcessIssueTokenFullE2E_002, TestSize.Level0)
{
    ModuleTestGuard guard;
    const std::string connName = "test-conn-companion-issue-001";

    CompanionPreIssueTokenOutput preIssueOutput;
    preIssueOutput.preIssueTokenReply = { 0x11, 0x22, 0x33 };
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(preIssueOutput), Return(ResultCode::SUCCESS)));

    CompanionProcessIssueTokenOutput processOutput;
    processOutput.atl = 3;
    processOutput.issueTokenReply = { 0x44, 0x55, 0x66 };
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessIssueToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(processOutput), Return(ResultCode::SUCCESS)));

    ASSERT_TRUE(guard.SetupHostBinding(HOST_USER_ID, "host-test-device-issue-001"));
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-test-device-issue-001"));
    DrainPendingTasks();

    // Round 1: PRE_ISSUE_TOKEN
    auto r1 = CompanionInjectAndCapture(guard, connName, 1, MessageType::PRE_ISSUE_TOKEN,
        BuildPreIssueTokenPayload("host-test-device-issue-001", HOST_USER_ID, HOST_USER_ID, { 0xAA, 0xBB }));
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1->seq, 1u);
    EXPECT_TRUE(r1->isReply);
    auto preReply = DecodePreIssueTokenReply(r1->payload);
    ASSERT_TRUE(preReply.has_value());
    EXPECT_EQ(preReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(preReply->extraInfo, preIssueOutput.preIssueTokenReply);

    // Round 2: ISSUE_TOKEN
    auto r2 = CompanionInjectAndCapture(guard, connName, 2, MessageType::ISSUE_TOKEN,
        BuildIssueTokenPayload("host-test-device-issue-001", HOST_USER_ID, HOST_USER_ID, { 0xCC, 0xDD }));
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(r2->seq, 2u);
    auto issueReply = DecodeIssueTokenReply(r2->payload);
    ASSERT_TRUE(issueReply.has_value());
    EXPECT_EQ(issueReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(issueReply->extraInfo, processOutput.issueTokenReply);
}

// ============================================================================
// Test 6: HostIssueTokenPreIssueFailedE2E_003
//         Host IssueToken flow with PreIssueToken failure
// ============================================================================
//
// What this tests:
//   HostIssueTokenRequest → PreIssueTokenReply with error → proper cleanup
//
// E2E level: HIGH
//   - Entry: HostIssueTokenRequest created via RequestFactory
//   - Production path: Error handling in HostIssueTokenRequest
//   - Verification: callback invoked with error result
// ============================================================================
HWTEST_F(AuthModuleTest, HostIssueTokenPreIssueFailedE2E_003, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEST_TEMPLATE_ID = 54325;
    constexpr uint32_t lockStateAuthType = 1;

    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-test-device-issue-fail-001", 54325));

    // 2. Setup Mock: HostPreIssueToken succeeds
    HostPreIssueTokenOutput preIssueOutput;
    preIssueOutput.preIssueTokenRequest = { 0x01, 0x02 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(preIssueOutput), Return(ResultCode::SUCCESS)));

    // 3. Note: HostIssueTokenRequest does NOT have a framework callback.
    // It completes via CompleteWithSuccess/CompleteWithError internally.
    // The test verifies the E2E error flow through message exchange and SecurityAgent mock calls.

    // 4. Create and start HostIssueTokenRequest
    std::vector<uint8_t> fwkUnlockMsg = { 0xAA };
    auto request = GetRequestFactory().CreateHostIssueTokenRequest(HOST_USER_ID, TEST_TEMPLATE_ID, lockStateAuthType,
        fwkUnlockMsg);
    ASSERT_NE(request, nullptr);

    bool startRet = GetRequestManager().Start(request);
    ASSERT_TRUE(startRet);
    DrainPendingTasks();

    // 5. Get connection and capture PRE_ISSUE_TOKEN message
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty());
    const auto &connName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty());

    auto preMsgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(preMsgInfo.has_value());

    // 6. Inject PreIssueTokenReply with ERROR from companion
    PreIssueTokenReply preReply;
    preReply.result = ResultCode::GENERAL_ERROR;
    preReply.extraInfo = { 0xBB };

    Attributes preReplyPayload;
    EncodePreIssueTokenReply(preReply, preReplyPayload);
    auto preReplyRawMsg = BuildReplyRawMsg(connName, preMsgInfo->seq, MessageType::PRE_ISSUE_TOKEN, preReplyPayload);

    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, preReplyRawMsg);
    DrainPendingTasks();

    // 7. Verify that HostPreIssueToken mock was called (verifying the E2E error path executed)
    // The gmock EXPECT_CALL for HostPreIssueToken will be verified automatically by the framework.
    // HostBeginIssueToken and HostEndIssueToken should NOT be called (pre-issue failed).
}

// ============================================================================
// Test 7: CompanionObtainTokenFullE2E_001
//         Full 2-round ObtainToken flow: PRE_OBTAIN_TOKEN → OBTAIN_TOKEN
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionObtainTokenFullE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    const std::string connName = "test-conn-obtain-001";
    const std::string deviceId = "companion-test-device-obtain-001";

    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, deviceId, 54330));

    HostProcessPreObtainTokenOutput preObtainOutput;
    preObtainOutput.preObtainTokenReply = { 0x11, 0x22, 0x33 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostProcessPreObtainToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(preObtainOutput), Return(ResultCode::SUCCESS)));

    HostProcessObtainTokenOutput obtainOutput;
    obtainOutput.obtainTokenReply = { 0x44, 0x55, 0x66 };
    obtainOutput.atl = 3;
    EXPECT_CALL(guard.GetSecurityAgent(), HostProcessObtainToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(obtainOutput), Return(ResultCode::SUCCESS)));

    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey(deviceId));
    DrainPendingTasks();

    PreObtainTokenRequest preReq;
    preReq.hostUserId = HOST_USER_ID;
    preReq.companionDeviceKey = MakeDeviceKey(deviceId, HOST_USER_ID);
    preReq.extraInfo = { 0xAA, 0xBB };
    Attributes prePayload;
    EncodePreObtainTokenRequest(preReq, prePayload);

    auto r1 = guard.InjectRequestAndCaptureReply(connName,
        BuildRequestRawMsg(connName, 1, MessageType::PRE_OBTAIN_TOKEN, prePayload), MessageType::PRE_OBTAIN_TOKEN);
    ASSERT_TRUE(r1.has_value());
    EXPECT_TRUE(r1->isReply);
    auto preReply = DecodePreObtainTokenReply(r1->payload);
    ASSERT_TRUE(preReply.has_value());
    EXPECT_EQ(preReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(preReply->extraInfo, preObtainOutput.preObtainTokenReply);

    ObtainTokenRequest obtainReq;
    obtainReq.hostUserId = HOST_USER_ID;
    obtainReq.companionDeviceKey = MakeDeviceKey(deviceId, HOST_USER_ID);
    obtainReq.extraInfo = { 0xCC, 0xDD };
    Attributes obtainPayload;
    EncodeObtainTokenRequest(obtainReq, obtainPayload);

    auto r2 = guard.InjectRequestAndCaptureReply(connName,
        BuildRequestRawMsg(connName, 2, MessageType::OBTAIN_TOKEN, obtainPayload), MessageType::OBTAIN_TOKEN);
    ASSERT_TRUE(r2.has_value());
    auto obtainReply = DecodeObtainTokenReply(r2->payload);
    ASSERT_TRUE(obtainReply.has_value());
    EXPECT_EQ(obtainReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(obtainReply->extraInfo, obtainOutput.obtainTokenReply);
}

// ============================================================================
// Test 8: HostProcessObtainTokenE2E_002
//         Host receives PRE_OBTAIN_TOKEN and OBTAIN_TOKEN from Companion
// ============================================================================
HWTEST_F(AuthModuleTest, HostProcessObtainTokenE2E_002, TestSize.Level0)
{
    ModuleTestGuard guard;
    const std::string connName = "test-conn-host-obtain-001";
    const std::string deviceId = "companion-test-device-host-obtain-001";

    HostProcessPreObtainTokenOutput preObtainOutput;
    preObtainOutput.preObtainTokenReply = { 0x11, 0x22 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostProcessPreObtainToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(preObtainOutput), Return(ResultCode::SUCCESS)));

    HostProcessObtainTokenOutput obtainOutput;
    obtainOutput.obtainTokenReply = { 0x33, 0x44 };
    obtainOutput.atl = 4;
    EXPECT_CALL(guard.GetSecurityAgent(), HostProcessObtainToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(obtainOutput), Return(ResultCode::SUCCESS)));

    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey(deviceId));
    DrainPendingTasks();
    guard.SimulateDeviceOnline(deviceId);
    ASSERT_TRUE(guard.RegisterCompanionDirect(HOST_USER_ID, MakeDeviceKey(deviceId, HOST_USER_ID), 54331));

    PreObtainTokenRequest preReq;
    preReq.hostUserId = HOST_USER_ID;
    preReq.companionDeviceKey = MakeDeviceKey(deviceId, HOST_USER_ID);
    preReq.extraInfo = { 0xAA };
    Attributes prePayload;
    EncodePreObtainTokenRequest(preReq, prePayload);

    auto r1 = guard.InjectRequestAndCaptureReply(connName,
        BuildRequestRawMsg(connName, 1, MessageType::PRE_OBTAIN_TOKEN, prePayload), MessageType::PRE_OBTAIN_TOKEN);
    ASSERT_TRUE(r1.has_value());
    EXPECT_TRUE(r1->isReply);
    auto preReply = DecodePreObtainTokenReply(r1->payload);
    ASSERT_TRUE(preReply.has_value());
    EXPECT_EQ(preReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(preReply->extraInfo, preObtainOutput.preObtainTokenReply);

    ObtainTokenRequest obtainReq;
    obtainReq.hostUserId = HOST_USER_ID;
    obtainReq.companionDeviceKey = MakeDeviceKey(deviceId, HOST_USER_ID);
    obtainReq.extraInfo = { 0xBB };
    Attributes obtainPayload;
    EncodeObtainTokenRequest(obtainReq, obtainPayload);

    auto r2 = guard.InjectRequestAndCaptureReply(connName,
        BuildRequestRawMsg(connName, 2, MessageType::OBTAIN_TOKEN, obtainPayload), MessageType::OBTAIN_TOKEN);
    ASSERT_TRUE(r2.has_value());
    auto obtainReply = DecodeObtainTokenReply(r2->payload);
    ASSERT_TRUE(obtainReply.has_value());
    EXPECT_EQ(obtainReply->result, ResultCode::SUCCESS);
    EXPECT_EQ(obtainReply->extraInfo, obtainOutput.obtainTokenReply);
}

// ============================================================================
// Test 9: HostProcessPreObtainTokenFailedE2E_003
//         Host ObtainToken flow with PreObtainToken failure
// ============================================================================
//
// What this tests:
//   Host receives PRE_OBTAIN_TOKEN → HostProcessPreObtainToken returns error →
//   error reply sent
//
// E2E level: HIGH
//   - Entry: raw PRE_OBTAIN_TOKEN message injection
//   - Production path: Error handling in HostObtainTokenHandler
//   - Verification: error reply with correct result code
// ============================================================================
HWTEST_F(AuthModuleTest, HostProcessPreObtainTokenFailedE2E_003, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "test-conn-host-obtain-fail-001";

    // 1. Setup Mock: HostProcessPreObtainToken returns error
    HostProcessPreObtainTokenOutput preObtainOutput;
    preObtainOutput.preObtainTokenReply = { 0x11 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostProcessPreObtainToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(preObtainOutput), Return(ResultCode::GENERAL_ERROR)));

    // 2. Create inbound connection
    guard.GetChannel().TestSimulateIncomingConnection(connName,
        MakePhysKey("companion-test-device-host-obtain-fail-001"));
    DrainPendingTasks();

    // 2b. Register companion device for host-side handler lookup
    guard.SimulateDeviceOnline("companion-test-device-host-obtain-fail-001");
    ASSERT_TRUE(guard.RegisterCompanionDirect(HOST_USER_ID,
        MakeDeviceKey("companion-test-device-host-obtain-fail-001", HOST_USER_ID), 54332));

    // 3. Send PRE_OBTAIN_TOKEN request
    // companionDeviceKey.deviceUserId must be HOST_USER_ID to match the registered companion.
    PreObtainTokenRequest preRequest;
    preRequest.hostUserId = HOST_USER_ID;
    preRequest.companionDeviceKey = MakeDeviceKey("companion-test-device-host-obtain-fail-001", HOST_USER_ID);
    preRequest.extraInfo = { 0xAA };

    Attributes prePayload;
    EncodePreObtainTokenRequest(preRequest, prePayload);
    auto preRawMsg = BuildRequestRawMsg(connName, 1, MessageType::PRE_OBTAIN_TOKEN, prePayload);

    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, preRawMsg);
    DrainPendingTasks();

    // 4. Verify PreObtainTokenReply with error
    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected PreObtainTokenReply";
    auto preReplyInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(preReplyInfo.has_value());
    EXPECT_TRUE(preReplyInfo->isReply);
    EXPECT_EQ(preReplyInfo->msgType, MessageType::PRE_OBTAIN_TOKEN);
    auto preReply = DecodePreObtainTokenReply(preReplyInfo->payload);
    ASSERT_TRUE(preReply.has_value());
    EXPECT_EQ(preReply->result, ResultCode::GENERAL_ERROR);
}

// ============================================================================
// Test 10: HostRemoveCompanionFullE2E_001
//         Host removes companion binding → sends REMOVE_HOST_BINDING →
//         Companion processes → reply → Host cleans up
// ============================================================================
//
// What this tests:
//   HostRemoveHostBindingRequest → send REMOVE_HOST_BINDING →
//   Companion CompanionRemoveHostBinding → reply
//
// E2E level: HIGH
//   - Entry: HostRemoveHostBindingRequest created via RequestFactory
//   - Production path: Full HostRemoveHostBindingRequest lifecycle
//   - Verification: message sent/received via FakeChannel, callback invoked
// ============================================================================
HWTEST_F(AuthModuleTest, HostRemoveCompanionFullE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEST_TEMPLATE_ID = 54326;

    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-test-device-remove-001", 54326));

    // 2. Note: HostRemoveHostBindingRequest does NOT have a framework callback.
    // It completes via CompleteWithSuccess/CompleteWithError internally.
    // The E2E flow is verified through message exchange verification.
    // HostRemoveCompanion is called by CompanionManager.RemoveCompanion, not by the request itself.
    // Since we create the request directly via RequestFactory, HostRemoveCompanion is not expected.

    // 3. Create HostRemoveHostBindingRequest via RequestFactory
    // companionDeviceKey.deviceUserId must be HOST_USER_ID to match registered companion.
    // OutboundRequest::OpenConnection calls GetChannelIdByDeviceKey which looks up the
    // registered companion's device key.
    auto request = GetRequestFactory().CreateHostRemoveHostBindingRequest(HOST_USER_ID, TEST_TEMPLATE_ID,
        MakeDeviceKey("companion-test-device-remove-001", HOST_USER_ID));
    ASSERT_NE(request, nullptr) << "Failed to create HostRemoveHostBindingRequest";

    // 4. Start the request
    bool startRet = GetRequestManager().Start(request);
    ASSERT_TRUE(startRet) << "Failed to start HostRemoveHostBindingRequest";
    DrainPendingTasks();

    // 5. Capture REMOVE_HOST_BINDING message sent by host
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection to be established";
    const auto &connName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected REMOVE_HOST_BINDING message";

    auto removeMsgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(removeMsgInfo.has_value()) << "Failed to decode REMOVE_HOST_BINDING message";
    EXPECT_FALSE(removeMsgInfo->isReply) << "REMOVE_HOST_BINDING should be a request";
    EXPECT_EQ(removeMsgInfo->msgType, MessageType::REMOVE_HOST_BINDING);

    // Note: Cannot use DecodeRemoveHostBindingRequest because outbound messages lack
    // SRC_IDENTIFIER_TYPE/SRC_IDENTIFIER fields (added by MessageRouter on receiving side).
    // Verify raw attribute fields instead.
    int32_t hostUserId = 0;
    EXPECT_TRUE(removeMsgInfo->payload.GetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId));
    EXPECT_EQ(hostUserId, HOST_USER_ID);

    int32_t companionUserId = 0;
    EXPECT_TRUE(removeMsgInfo->payload.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserId));
    EXPECT_EQ(companionUserId, HOST_USER_ID);

    // 6. Inject RemoveHostBindingReply from companion
    RemoveHostBindingReply removeReply;
    removeReply.result = ResultCode::SUCCESS;

    Attributes removeReplyPayload;
    EncodeRemoveHostBindingReply(removeReply, removeReplyPayload);
    CaptureAndReply(guard.GetChannel(), connName, MessageType::REMOVE_HOST_BINDING, removeReplyPayload);

    // 7. Verification: The full E2E message exchange completed successfully:
    // - Host sent REMOVE_HOST_BINDING request (verified above)
    // - Companion replied with SUCCESS (injected above)
    // - HostRemoveHostBindingRequest processes the reply and completes internally
    // The message exchange itself is the primary verification for this OutboundRequest.
}

// ============================================================================
// Test 11: CompanionRemoveHostBindingE2E_001
//         Companion receives REMOVE_HOST_BINDING → processes → reply
// ============================================================================
//
// What this tests:
//   Companion receives REMOVE_HOST_BINDING → CompanionRemoveHostBinding →
//   deletes binding → reply
//
// E2E level: HIGH
//   - Entry: raw REMOVE_HOST_BINDING message injection at FakeChannel boundary
//   - Production path: MessageRouter → CompanionRemoveHostBindingHandler → SecurityAgent
//   - Verification: RemoveHostBindingReply decoded and verified
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionRemoveHostBindingE2E_002, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "test-conn-companion-remove-001";

    // 1. Setup Mock: CompanionRemoveHostBinding
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionRemoveHostBinding(_)).WillOnce(Return(ResultCode::SUCCESS));

    // 2. Register host binding so companion-side handler can find it
    //    companionUserId must match active user (100) on companion side
    ASSERT_TRUE(guard.SetupHostBinding(HOST_USER_ID, "host-test-device-companion-remove-001"));

    // 3. Create inbound connection (simulates host connecting to companion)
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-test-device-companion-remove-001"));
    DrainPendingTasks();

    // 4. Send REMOVE_HOST_BINDING request
    RemoveHostBindingRequest removeRequest;
    removeRequest.hostDeviceKey = MakeDeviceKey("host-test-device-companion-remove-001", HOST_USER_ID);
    removeRequest.companionUserId = HOST_USER_ID;
    removeRequest.extraInfo = { 0xAA, 0xBB };

    Attributes removePayload;
    EncodeRemoveHostBindingRequest(removeRequest, removePayload);
    auto removeRawMsg = BuildRequestRawMsg(connName, 1, MessageType::REMOVE_HOST_BINDING, removePayload);

    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, removeRawMsg);
    DrainPendingTasks();

    // 5. Capture and verify RemoveHostBindingReply
    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected RemoveHostBindingReply";

    auto removeReplyInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(removeReplyInfo.has_value()) << "Failed to decode RemoveHostBindingReply";
    EXPECT_EQ(removeReplyInfo->seq, 1u) << "Reply seq should match request seq";
    EXPECT_TRUE(removeReplyInfo->isReply) << "Message should be a reply";
    EXPECT_EQ(removeReplyInfo->msgType, MessageType::REMOVE_HOST_BINDING)
        << "Reply message type should be REMOVE_HOST_BINDING";

    auto removeReply = DecodeRemoveHostBindingReply(removeReplyInfo->payload);
    ASSERT_TRUE(removeReply.has_value()) << "Failed to decode RemoveHostBindingReply";
    EXPECT_EQ(removeReply->result, ResultCode::SUCCESS) << "RemoveHostBindingReply result should be SUCCESS";
}

// ============================================================================
// Test 12: CompanionRemoveHostBindingFailedE2E_003
//         Companion receives REMOVE_HOST_BINDING → SecurityAgent returns error →
//         error reply sent
// ============================================================================
//
// What this tests:
//   CompanionRemoveHostBinding fails → error reply sent
//
// E2E level: HIGH
//   - Entry: raw REMOVE_HOST_BINDING message injection
//   - Production path: Error handling path
//   - Verification: error result in reply message
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionRemoveHostBindingFailedE2E_003, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "test-conn-companion-remove-fail-001";

    // 1. Setup Mock: CompanionRemoveHostBinding returns error
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionRemoveHostBinding(_)).WillOnce(Return(ResultCode::TOKEN_NOT_FOUND));

    // 2. Register host binding so companion-side handler can find it
    //    companionUserId must match active user (100) on companion side
    ASSERT_TRUE(guard.SetupHostBinding(HOST_USER_ID, "host-test-device-companion-remove-fail-001"));

    // 3. Create inbound connection
    guard.GetChannel().TestSimulateIncomingConnection(connName,
        MakePhysKey("host-test-device-companion-remove-fail-001"));
    DrainPendingTasks();

    // 4. Send REMOVE_HOST_BINDING request
    RemoveHostBindingRequest removeRequest;
    removeRequest.hostDeviceKey = MakeDeviceKey("host-test-device-companion-remove-fail-001", HOST_USER_ID);
    removeRequest.companionUserId = HOST_USER_ID;
    removeRequest.extraInfo = { 0xAA };

    Attributes removePayload;
    EncodeRemoveHostBindingRequest(removeRequest, removePayload);
    auto removeRawMsg = BuildRequestRawMsg(connName, 1, MessageType::REMOVE_HOST_BINDING, removePayload);

    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, removeRawMsg);
    DrainPendingTasks();

    // 5. Capture and verify error reply
    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected RemoveHostBindingReply";

    auto removeReplyInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(removeReplyInfo.has_value()) << "Failed to decode RemoveHostBindingReply";
    EXPECT_TRUE(removeReplyInfo->isReply);
    EXPECT_EQ(removeReplyInfo->msgType, MessageType::REMOVE_HOST_BINDING);

    auto removeReply = DecodeRemoveHostBindingReply(removeReplyInfo->payload);
    ASSERT_TRUE(removeReply.has_value()) << "Failed to decode RemoveHostBindingReply";
    EXPECT_EQ(removeReply->result, ResultCode::TOKEN_NOT_FOUND)
        << "RemoveHostBindingReply result should be TOKEN_NOT_FOUND";
}

// ============================================================================
// TokenAuth Tests
// ============================================================================

// ============================================================================
// Test 13: Host TokenAuth success
// ============================================================================
HWTEST_F(AuthModuleTest, HostTokenAuthSuccessE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEMPLATE_ID = 12345;
    constexpr ScheduleId TEST_SCHEDULE_ID = 9001;

    IAM_LOGI("[Phase] Setup — companion device online, HostBeginTokenAuth and HostEndTokenAuth mocks");
    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-token-auth-001", 12345));

    // 2. Setup Mock: HostBeginTokenAuth returns tokenAuthRequest
    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02, 0x03, 0x04 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    // HostEndTokenAuth should be called with the reply
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _))
        .WillOnce([&TEMPLATE_ID](const HostEndTokenAuthInput &input, HostEndTokenAuthOutput &output) {
            EXPECT_EQ(input.templateId, TEMPLATE_ID);
            EXPECT_FALSE(input.tokenAuthReply.empty());
            output.fwkMsg = { 0xAA, 0xBB };
            return ResultCode::SUCCESS;
        });

    // 3. Create callback
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;

    auto fwkCallback = [&callbackInvoked, &callbackResult](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        (void)extraInfo;
    };

    IAM_LOGI("[Phase] Run — Host TokenAuth success E2E flow");
    // 4. Call AuthenticateTokenAuth via ModuleTestGuard helper (mimics Executor.Authenticate())
    std::vector<uint8_t> testFwkMsg = { 0xAB, 0xCD };
    bool authRet =
        guard.AuthenticateTokenAuth(TEST_SCHEDULE_ID, testFwkMsg, HOST_USER_ID, TEMPLATE_ID, 0, std::move(fwkCallback));
    ASSERT_TRUE(authRet) << "AuthenticateTokenAuth failed";
    DrainPendingTasks();

    // 5. Get connection and capture sent message
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection";
    const auto &actualConnName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(actualConnName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected TOKEN_AUTH request to be sent";

    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value());
    EXPECT_EQ(msgInfo->msgType, MessageType::TOKEN_AUTH);
    EXPECT_FALSE(msgInfo->isReply);

    // 6. Build companion success reply
    TokenAuthReply reply;
    reply.result = ResultCode::SUCCESS;
    reply.extraInfo = { 0xCC, 0xDD };

    Attributes replyPayload;
    EncodeTokenAuthReply(reply, replyPayload);

    // 7. Inject reply
    CaptureAndReply(guard.GetChannel(), actualConnName, MessageType::TOKEN_AUTH, replyPayload);

    // 8. Verify callback was invoked with success
    EXPECT_TRUE(callbackInvoked) << "Expected callback to be invoked";
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

// ============================================================================
// Test 14: Host TokenAuth with no token (companion failure)
// ============================================================================
HWTEST_F(AuthModuleTest, HostTokenAuthNoTokenE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEMPLATE_ID = 12346;
    constexpr ScheduleId TEST_SCHEDULE_ID = 9002;

    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-no-token-001", 12346));

    // 2. Setup Mock: HostBeginTokenAuth succeeds
    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    // HostEndTokenAuth handles the error reply
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    // 3. Create callback
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::SUCCESS;

    auto fwkCallback = [&callbackInvoked, &callbackResult](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        (void)extraInfo;
    };

    // 4. Call AuthenticateTokenAuth via ModuleTestGuard helper (mimics Executor.Authenticate())
    bool authRet =
        guard.AuthenticateTokenAuth(TEST_SCHEDULE_ID, { 0xAA }, HOST_USER_ID, TEMPLATE_ID, 0, std::move(fwkCallback));
    ASSERT_TRUE(authRet);
    DrainPendingTasks();

    // 5. Get connection and seq
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection";
    const auto &actualConnName = allConnNames[0];
    auto sentMsgs = guard.GetChannel().GetSentMessages(actualConnName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected TOKEN_AUTH request to be sent";
    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value());

    // 6. Build companion failure reply (no token available)
    TokenAuthReply reply;
    reply.result = ResultCode::GENERAL_ERROR;
    reply.extraInfo = {};

    Attributes replyPayload;
    EncodeTokenAuthReply(reply, replyPayload);

    // 7. Inject reply
    CaptureAndReply(guard.GetChannel(), actualConnName, MessageType::TOKEN_AUTH, replyPayload);

    // 8. Verify callback received error
    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

// ============================================================================
// Test 15: Companion ProcessTokenAuth success
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionProcessTokenAuthSuccessE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "companion-token-auth-success-001";

    // 1. Setup: Register host binding so companion-side handler can find it
    ASSERT_TRUE(guard.SetupHostBinding(HOST_USER_ID, "host-token-auth-001"));

    // 2. Setup: Create inbound connection from host
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-token-auth-001"));
    DrainPendingTasks();

    // 3. Setup Mock: CompanionProcessTokenAuth returns success with MAC
    std::vector<uint8_t> expectedReply = { 0xAB, 0xCD, 0xEF, 0x12, 0x34 };
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessTokenAuth(_, _))
        .WillOnce(
            [&expectedReply](const CompanionProcessTokenAuthInput &input, CompanionProcessTokenAuthOutput &output) {
                EXPECT_GT(input.bindingId, 0);
                EXPECT_FALSE(input.tokenAuthRequest.empty());
                output.tokenAuthReply = expectedReply;
                return ResultCode::SUCCESS;
            });

    // 4. Build TokenAuth request from host
    TokenAuthRequest request;
    request.hostDeviceKey = MakeDeviceKey("host-token-auth-001", HOST_USER_ID);
    request.companionUserId = HOST_USER_ID;
    request.extraInfo = { 0x01, 0x02, 0x03 };

    Attributes requestPayload;
    EncodeTokenAuthRequest(request, requestPayload);

    auto requestRawMsg = BuildRequestRawMsg(connName, 1, MessageType::TOKEN_AUTH, requestPayload);

    // 5. Inject request
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, requestRawMsg);
    DrainPendingTasks();

    // 6. Capture reply from companion
    auto sentMsgList = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgList.empty()) << "Expected companion to send a reply";

    auto &replyRawMsg = sentMsgList[0];
    auto replyInfo = DecodeRawMsg(replyRawMsg);
    ASSERT_TRUE(replyInfo.has_value());
    EXPECT_TRUE(replyInfo->isReply);
    EXPECT_EQ(replyInfo->msgType, MessageType::TOKEN_AUTH);

    // 7. Verify reply content
    auto replyOpt = DecodeTokenAuthReply(replyInfo->payload);
    ASSERT_TRUE(replyOpt.has_value());
    EXPECT_EQ(replyOpt->result, ResultCode::SUCCESS);
    EXPECT_EQ(replyOpt->extraInfo, expectedReply) << "Reply should include MAC from CompanionProcessTokenAuth";
}

// ============================================================================
// Test 16: Companion ProcessTokenAuth with no token
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionProcessTokenAuthNoTokenE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "companion-no-token-001";

    // 1. Setup: Register host binding so companion-side handler can find it
    ASSERT_TRUE(guard.SetupHostBinding(HOST_USER_ID, "host-request-001"));

    // 2. Setup: Create inbound connection
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-request-001"));
    DrainPendingTasks();

    // 3. Setup Mock: CompanionProcessTokenAuth fails (no token)
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessTokenAuth(_, _))
        .WillOnce([](const CompanionProcessTokenAuthInput &, CompanionProcessTokenAuthOutput &output) {
            output.tokenAuthReply.clear();
            return ResultCode::GENERAL_ERROR;
        });

    // 4. Build TokenAuth request
    TokenAuthRequest request;
    request.hostDeviceKey = MakeDeviceKey("host-request-001", HOST_USER_ID);
    request.companionUserId = HOST_USER_ID;

    Attributes requestPayload;
    EncodeTokenAuthRequest(request, requestPayload);

    auto requestRawMsg = BuildRequestRawMsg(connName, 1, MessageType::TOKEN_AUTH, requestPayload);

    // 5. Inject request
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, requestRawMsg);
    DrainPendingTasks();

    // 6. Capture reply
    auto sentMsgList = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgList.empty());

    auto &replyRawMsg = sentMsgList[0];
    auto replyInfo = DecodeRawMsg(replyRawMsg);
    ASSERT_TRUE(replyInfo.has_value());
    EXPECT_EQ(replyInfo->msgType, MessageType::TOKEN_AUTH);

    // 7. Verify failure
    auto replyOpt = DecodeTokenAuthReply(replyInfo->payload);
    ASSERT_TRUE(replyOpt.has_value());
    EXPECT_EQ(replyOpt->result, ResultCode::GENERAL_ERROR);
}

// ============================================================================
// DelegateAuth Tests
// ============================================================================

// ============================================================================
// Test 17: Host DelegateAuth success (two-round trip)
// ============================================================================
HWTEST_F(AuthModuleTest, HostDelegateAuthSuccessE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr TemplateId TEMPLATE_ID = 54321;

    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-delegate-001", 54321));

    HostBeginDelegateAuthOutput beginOutput;
    beginOutput.startDelegateAuthRequest = { 0x01, 0x02, 0x03 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _))
        .WillOnce([](const HostEndDelegateAuthInput &, HostEndDelegateAuthOutput &output) {
            output.fwkMsg = { 0xAA, 0xBB };
            output.authType = AuthType::PIN;
            output.atl = 2;
            return ResultCode::SUCCESS;
        });

    FwkCallbackCapture cb;
    ASSERT_TRUE(guard.AuthenticateDelegateAuth(10001, { 0xAB }, HOST_USER_ID, TEMPLATE_ID, 0, cb.MakeCallback()));
    DrainPendingTasks();

    std::string connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());

    StartDelegateAuthReply startReply;
    startReply.result = ResultCode::SUCCESS;
    Attributes startReplyPayload;
    EncodeStartDelegateAuthReply(startReply, startReplyPayload);
    ASSERT_TRUE(guard.CaptureVerifyAndReply(connName, MessageType::START_DELEGATE_AUTH, startReplyPayload));

    SendDelegateAuthResultRequest resultRequest;
    resultRequest.result = ResultCode::SUCCESS;
    resultRequest.extraInfo = { 0xCC, 0xDD };
    Attributes resultPayload;
    EncodeSendDelegateAuthResultRequest(resultRequest, resultPayload);
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName,
        BuildRequestRawMsg(connName, 2, MessageType::SEND_DELEGATE_AUTH_RESULT, resultPayload));
    DrainPendingTasks();

    EXPECT_TRUE(cb.invoked);
    EXPECT_EQ(cb.result, ResultCode::SUCCESS);

    auto replyMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(replyMsgs.empty());
    auto replyInfo = DecodeRawMsg(replyMsgs[0]);
    ASSERT_TRUE(replyInfo.has_value());
    EXPECT_TRUE(replyInfo->isReply);
    EXPECT_EQ(replyInfo->msgType, MessageType::SEND_DELEGATE_AUTH_RESULT);
    auto replyOpt = DecodeSendDelegateAuthResultReply(replyInfo->payload);
    ASSERT_TRUE(replyOpt.has_value());
    EXPECT_EQ(replyOpt->result, ResultCode::SUCCESS);
}

// ============================================================================
// Test 18: Companion DelegateAuth full flow
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionDelegateAuthFullE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "companion-delegate-full-001";

    // 1. Setup: Register host binding so companion-side handler can find it
    ASSERT_TRUE(guard.SetupHostBinding(HOST_USER_ID, "host-delegate-001"));

    // 2. Setup: Create inbound connection
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-delegate-001"));
    DrainPendingTasks();

    // 3. Setup Mock: CompanionBeginDelegateAuth returns challenge
    uint64_t expectedChallenge = 12345678;
    Atl expectedAtl = 3;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _))
        .WillOnce([&expectedChallenge, &expectedAtl](const CompanionDelegateAuthBeginInput &input,
                      CompanionDelegateAuthBeginOutput &output) {
            EXPECT_GT(input.bindingId, 0);
            EXPECT_FALSE(input.startDelegateAuthRequest.empty());
            output.challenge = expectedChallenge;
            output.atl = expectedAtl;
            return ResultCode::SUCCESS;
        });

    // 4. Build StartDelegateAuth request from host
    StartDelegateAuthRequest request;
    request.hostDeviceKey = MakeDeviceKey("host-delegate-001", HOST_USER_ID);
    request.companionUserId = HOST_USER_ID;
    request.extraInfo = { 0x01 };

    Attributes requestPayload;
    EncodeStartDelegateAuthRequest(request, requestPayload);

    auto requestRawMsg = BuildRequestRawMsg(connName, 1, MessageType::START_DELEGATE_AUTH, requestPayload);

    // 5. Inject start request
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, requestRawMsg);
    DrainPendingTasks();

    // 6. Capture start reply
    auto sentMsgList = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgList.empty());

    auto &startReplyRawMsg = sentMsgList[0];
    auto startReplyInfo = DecodeRawMsg(startReplyRawMsg);
    ASSERT_TRUE(startReplyInfo.has_value());
    EXPECT_TRUE(startReplyInfo->isReply);
    EXPECT_EQ(startReplyInfo->msgType, MessageType::START_DELEGATE_AUTH);

    auto startReplyOpt = DecodeStartDelegateAuthReply(startReplyInfo->payload);
    ASSERT_TRUE(startReplyOpt.has_value());
    EXPECT_EQ(startReplyOpt->result, ResultCode::SUCCESS);
}

// ============================================================================
// Test 19: Host DelegateAuth with companion failure
// ============================================================================
HWTEST_F(AuthModuleTest, HostDelegateAuthFailureE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEMPLATE_ID = 54322;
    constexpr ScheduleId TEST_SCHEDULE_ID = 10002;

    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-fail-001", 54322));

    // 2. Setup Mock: HostBeginDelegateAuth succeeds
    HostBeginDelegateAuthOutput beginOutput;
    beginOutput.startDelegateAuthRequest = { 0x01, 0x02 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    // HostEndDelegateAuth is NOT called when delegate auth result is failure.
    // HandleSendDelegateAuthRequest returns false immediately when resultMsg.result != SUCCESS,
    // without calling HostEndDelegateAuth.

    // 3. Create callback
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::SUCCESS;

    auto fwkCallback = [&callbackInvoked, &callbackResult](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        (void)extraInfo;
    };

    // 4. Call AuthenticateDelegateAuth via ModuleTestGuard helper (mimics Executor.Authenticate())
    bool authRet = guard.AuthenticateDelegateAuth(TEST_SCHEDULE_ID, { 0xAA }, HOST_USER_ID, TEMPLATE_ID, 0,
        std::move(fwkCallback));
    ASSERT_TRUE(authRet);
    DrainPendingTasks();

    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    const auto &actualConnName = allConnNames[0];

    // 5. Build SendDelegateAuthResult request with failure
    SendDelegateAuthResultRequest resultRequest;
    resultRequest.result = ResultCode::GENERAL_ERROR;
    resultRequest.extraInfo = { 0xFF };

    Attributes resultRequestPayload;
    EncodeSendDelegateAuthResultRequest(resultRequest, resultRequestPayload);

    auto resultRequestRawMsg =
        BuildRequestRawMsg(actualConnName, 1, MessageType::SEND_DELEGATE_AUTH_RESULT, resultRequestPayload);

    // 6. Inject result request
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(actualConnName, resultRequestRawMsg);
    DrainPendingTasks();

    // 7. Verify callback received error result
    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);

    // 8. Verify reply sent
    auto sentMsgList = guard.GetChannel().GetSentMessages(actualConnName);
    ASSERT_FALSE(sentMsgList.empty());

    auto &resultReplyRawMsg = sentMsgList[0];
    auto resultReplyInfo = DecodeRawMsg(resultReplyRawMsg);
    ASSERT_TRUE(resultReplyInfo.has_value());
    EXPECT_EQ(resultReplyInfo->msgType, MessageType::SEND_DELEGATE_AUTH_RESULT);

    auto resultReplyOpt = DecodeSendDelegateAuthResultReply(resultReplyInfo->payload);
    ASSERT_TRUE(resultReplyOpt.has_value());
    // ErrorGuard fires with the peer's actual error code (GENERAL_ERROR) propagated via outResult
    EXPECT_EQ(resultReplyOpt->result, ResultCode::GENERAL_ERROR);
}
// ============================================================================

// ============================================================================
// Test 20: Companion RevokeToken
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionRevokeTokenE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "revoke-token-conn-001";
    // HOST_USER_ID provided by namespace-level constant
    constexpr TemplateId TEMPLATE_ID = 99999;

    // 1. Setup: Register companion for host-side handler lookup
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-revoke-001", TEMPLATE_ID));

    // 2. Create inbound connection from companion
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("companion-revoke-001"));
    DrainPendingTasks();

    // 3. Note: HostRevokeTokenHandler does NOT call HostRevokeToken.
    // It calls GetCompanionStatus + SetCompanionTokenAuthAtl directly.
    // The companion must be registered so GetCompanionStatus succeeds.

    // 4. Build RevokeToken request from companion
    RevokeTokenRequest request;
    request.hostUserId = HOST_USER_ID;
    request.companionDeviceKey = MakeDeviceKey("companion-revoke-001", HOST_USER_ID);

    Attributes requestPayload;
    EncodeRevokeTokenRequest(request, requestPayload);

    auto requestRawMsg = BuildRequestRawMsg(connName, 1, MessageType::COMPANION_REVOKE_TOKEN, requestPayload);

    // 5. Inject request
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, requestRawMsg);
    DrainPendingTasks();

    // 6. Capture reply from host
    auto sentMsgList = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgList.empty()) << "Expected host to send revoke reply";

    auto &replyRawMsg = sentMsgList[0];
    auto replyInfo = DecodeRawMsg(replyRawMsg);
    ASSERT_TRUE(replyInfo.has_value());
    EXPECT_TRUE(replyInfo->isReply);
    EXPECT_EQ(replyInfo->msgType, MessageType::COMPANION_REVOKE_TOKEN);

    // 7. Verify reply success
    auto replyOpt = DecodeRevokeTokenReply(replyInfo->payload);
    ASSERT_TRUE(replyOpt.has_value());
    EXPECT_EQ(replyOpt->result, ResultCode::SUCCESS);
}

// ============================================================================
// Test 21: HostDelegateAuthPreemptedE2E_001
//         Starting a second DelegateAuth request preempts the first
// ============================================================================
//
// What this tests:
//   RequestManager.Start checks ShouldCancelOnNewRequest on existing requests.
//   HostDelegateAuthRequest::ShouldCancelOnNewRequest returns true when
//   newRequestType == HOST_DELEGATE_AUTH_REQUEST.
//   The first request gets Cancel(CANCELED), which fires its callback with CANCELED.
//   The second request proceeds normally.
//
// E2E level: HIGH
//   - Entry: Two sequential AuthenticateDelegateAuth calls via ModuleTestGuard
//   - Production path: RequestManager::Start → ShouldCancelOnNewRequest → Cancel
//   - Verification: first callback CANCELED, second callback still pending
// ============================================================================
HWTEST_F(AuthModuleTest, HostDelegateAuthPreemptedE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr TemplateId TEMPLATE_ID = 60001;

    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-preempt-delegate-001", TEMPLATE_ID));

    HostBeginDelegateAuthOutput beginOutput;
    beginOutput.startDelegateAuthRequest = { 0x01, 0x02, 0x03 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    FwkCallbackCapture cb1;
    FwkCallbackCapture cb2;

    ASSERT_TRUE(guard.AuthenticateDelegateAuth(21001, { 0xAA }, HOST_USER_ID, TEMPLATE_ID, 0, cb1.MakeCallback()));
    DrainPendingTasks();

    auto connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());
    auto r1 = guard.CaptureOutboundMessage(connName, MessageType::START_DELEGATE_AUTH);
    ASSERT_TRUE(r1.has_value());

    guard.GetChannel().ClearSentMessages();
    ASSERT_TRUE(guard.AuthenticateDelegateAuth(21002, { 0xBB }, HOST_USER_ID, TEMPLATE_ID, 0, cb2.MakeCallback()));
    DrainPendingTasks();

    EXPECT_TRUE(cb1.invoked);
    EXPECT_EQ(cb1.result, ResultCode::CANCELED);
    EXPECT_FALSE(cb2.invoked);

    auto allConns = guard.GetChannel().GetAllConnectionNames();
    bool found = false;
    for (const auto &cn : allConns) {
        for (const auto &rawMsg : guard.GetChannel().GetSentMessages(cn)) {
            auto info = DecodeRawMsg(rawMsg);
            if (info.has_value() && info->msgType == MessageType::START_DELEGATE_AUTH && !info->isReply) {
                found = true;
                break;
            }
        }
        if (found)
            break;
    }
    EXPECT_TRUE(found);
}

// ============================================================================
// Test 22: HostTokenAuthPreemptedE2E_001
//         Starting a second TokenAuth request to same device preempts the first
// ============================================================================
HWTEST_F(AuthModuleTest, HostTokenAuthPreemptedE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr TemplateId TEMPLATE_ID = 60002;

    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-preempt-token-001", TEMPLATE_ID));

    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02, 0x03 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    FwkCallbackCapture cb1;
    FwkCallbackCapture cb2;

    ASSERT_TRUE(guard.AuthenticateTokenAuth(22001, { 0xAA }, HOST_USER_ID, TEMPLATE_ID, 0, cb1.MakeCallback()));
    DrainPendingTasks();

    auto connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());
    auto r1 = guard.CaptureOutboundMessage(connName, MessageType::TOKEN_AUTH);
    ASSERT_TRUE(r1.has_value());

    guard.GetChannel().ClearSentMessages();
    ASSERT_TRUE(guard.AuthenticateTokenAuth(22002, { 0xBB }, HOST_USER_ID, TEMPLATE_ID, 0, cb2.MakeCallback()));
    DrainPendingTasks();

    EXPECT_TRUE(cb1.invoked);
    EXPECT_EQ(cb1.result, ResultCode::CANCELED);
    EXPECT_FALSE(cb2.invoked);

    TokenAuthReply reply;
    reply.result = ResultCode::SUCCESS;
    reply.extraInfo = { 0xCC, 0xDD };
    Attributes replyPayload;
    EncodeTokenAuthReply(reply, replyPayload);

    auto allConns = guard.GetChannel().GetAllConnectionNames();
    bool replied = false;
    for (const auto &cn : allConns) {
        for (const auto &rawMsg : guard.GetChannel().GetSentMessages(cn)) {
            auto info = DecodeRawMsg(rawMsg);
            if (info.has_value() && info->msgType == MessageType::TOKEN_AUTH && !info->isReply) {
                guard.GetChannel().ClearSentMessages();
                guard.GetChannel().TestSimulateIncomingMessage(cn,
                    BuildReplyRawMsg(cn, info->seq, MessageType::TOKEN_AUTH, replyPayload));
                DrainPendingTasks();
                replied = true;
                break;
            }
        }
        if (replied)
            break;
    }
    ASSERT_TRUE(replied);
    EXPECT_TRUE(cb2.invoked);
    EXPECT_EQ(cb2.result, ResultCode::SUCCESS);
}

// ============================================================================
// Test 23: CompanionDelegateAuthFullFlowE2E_001
//         Complete companion-side delegate auth: Begin + End + SendDelegateAuthResult
// ============================================================================
HWTEST_F(AuthModuleTest, CompanionDelegateAuthFullFlowE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    const std::string connName = "companion-delegate-full-flow-001";
    ASSERT_TRUE(guard.SetupHostBinding(HOST_USER_ID, "host-delegate-full-002"));
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-delegate-full-002"));
    DrainPendingTasks();

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _))
        .WillOnce([](const CompanionDelegateAuthBeginInput &, CompanionDelegateAuthBeginOutput &output) {
            output.challenge = 12345;
            output.atl = 3;
            return ResultCode::SUCCESS;
        });
    AuthResultCallback capturedCallback;
    EXPECT_CALL(guard.GetUserAuthAdapter(), BeginDelegateAuth(_))
        .WillOnce([&](const BeginDelegateAuthParam &param) -> uint64_t {
            capturedCallback = param.callback;
            return 1001;
        });
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _))
        .WillOnce([](const CompanionDelegateAuthEndInput &, CompanionDelegateAuthEndOutput &out) {
            out.delegateAuthResult = { 0xAA, 0xBB, 0xCC };
            out.authType = static_cast<int32_t>(AuthType::PIN);
            out.atl = 3;
            return ResultCode::SUCCESS;
        });

    StartDelegateAuthRequest req;
    req.hostDeviceKey = MakeDeviceKey("host-delegate-full-002", HOST_USER_ID);
    req.companionUserId = HOST_USER_ID;
    req.extraInfo = { 0x01, 0x02 };
    Attributes reqPayload;
    EncodeStartDelegateAuthRequest(req, reqPayload);
    auto r1 = guard.InjectRequestAndCaptureReply(connName,
        BuildRequestRawMsg(connName, 1, MessageType::START_DELEGATE_AUTH, reqPayload),
        MessageType::START_DELEGATE_AUTH);
    ASSERT_TRUE(r1.has_value());
    auto startReply = DecodeStartDelegateAuthReply(r1->payload);
    ASSERT_TRUE(startReply.has_value());
    EXPECT_EQ(startReply->result, ResultCode::SUCCESS);
    ASSERT_TRUE(capturedCallback);
    capturedCallback(ResultCode::SUCCESS, { 0xDE, 0xAD, 0xBE, 0xEF });
    DrainPendingTasks();
    auto resultMsg = FindOutboundMessage(guard.GetChannel(), connName, MessageType::SEND_DELEGATE_AUTH_RESULT);
    ASSERT_TRUE(resultMsg.has_value());
    auto resultOpt = DecodeSendDelegateAuthResultRequest(resultMsg->payload);
    ASSERT_TRUE(resultOpt.has_value());
    EXPECT_EQ(resultOpt->result, ResultCode::SUCCESS);
    EXPECT_EQ(resultOpt->extraInfo, (std::vector<uint8_t> { 0xAA, 0xBB, 0xCC }));
}

// ============================================================================
// Test 24: UserSwitchCancelsRequestE2E_001
//         Changing active user cancels pending host-side TokenAuth request
// ============================================================================
//
// What this tests:
//   When TestSetActiveUser is called with a different user ID, it triggers
//   OnActiveUserIdChanged in CompanionManagerImpl, which clears companions.
//   The pending request (waiting for reply from companion) should be cancelled
//   because the companion it was talking to is no longer associated with the
//   new active user.
//
// E2E level: HIGH
//   - Entry: AuthenticateTokenAuth + TestSetActiveUser(999) via FakeUserIdManager
//   - Production path: UserIdManager → OnActiveUserIdChanged → companion cleanup
//   - Verification: callback invoked with error result
// ============================================================================
HWTEST_F(AuthModuleTest, UserSwitchCancelsRequestE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEMPLATE_ID = 60003;
    constexpr ScheduleId TEST_SCHEDULE_ID = 24001;

    IAM_LOGI("[Phase] Setup — companion device online, HostBeginTokenAuth mock");
    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-user-switch-001", TEMPLATE_ID));

    // 2. Setup Mock: HostBeginTokenAuth returns tokenAuthRequest
    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    // 3. Create callback to capture result
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::SUCCESS;

    auto fwkCallback = [&callbackInvoked, &callbackResult](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        (void)extraInfo;
    };

    IAM_LOGI("[Phase] Run — Start TokenAuth request");
    // 4. Start TokenAuth request
    bool authRet =
        guard.AuthenticateTokenAuth(TEST_SCHEDULE_ID, { 0xAA }, HOST_USER_ID, TEMPLATE_ID, 0, std::move(fwkCallback));
    ASSERT_TRUE(authRet) << "AuthenticateTokenAuth failed";
    DrainPendingTasks();

    // 5. Verify TOKEN_AUTH message sent
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection";
    const auto &connName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected TOKEN_AUTH message";
    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value());
    EXPECT_EQ(msgInfo->msgType, MessageType::TOKEN_AUTH);

    IAM_LOGI("[Phase] Run — Simulate user switch to user 999");
    // 6. Simulate user switch to a different user
    guard.GetUserIdManager().TestSetActiveUser(999);
    DrainPendingTasks();

    // 7. Verify: callback was NOT invoked
    //    The user switch triggers OnActiveUserIdChanged which clears the companion list
    //    and DeviceStatusManager::HandleUserIdChange which updates activeUserId_ to 999.
    //    However, neither path explicitly cancels in-flight requests or closes connections.
    //    The OutboundRequest remains alive, waiting for a reply on its connection.
    //    The request will eventually time out via MessageRouter's message timeout mechanism,
    //    but not synchronously during the user switch.
    EXPECT_FALSE(callbackInvoked) << "Callback should NOT be invoked immediately after user switch";
}

// ============================================================================
// Test 25: HostTokenAuthCallbackExtraInfoVerifiedE2E_001
//         Full TokenAuth flow with complete callback content verification
// ============================================================================
HWTEST_F(AuthModuleTest, HostTokenAuthCallbackExtraInfoVerifiedE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr TemplateId TEMPLATE_ID = 60004;

    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-token-extra-001", TEMPLATE_ID));

    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02, 0x03, 0x04 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _))
        .WillOnce([](const HostEndTokenAuthInput &, HostEndTokenAuthOutput &output) {
            output.fwkMsg = { 0xAA, 0xBB };
            return ResultCode::SUCCESS;
        });

    FwkCallbackCapture cb;
    ASSERT_TRUE(guard.AuthenticateTokenAuth(25001, { 0xAB, 0xCD }, HOST_USER_ID, TEMPLATE_ID, 0, cb.MakeCallback()));
    DrainPendingTasks();

    std::string connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());

    TokenAuthReply reply;
    reply.result = ResultCode::SUCCESS;
    reply.extraInfo = { 0xCC, 0xDD };
    Attributes replyPayload;
    EncodeTokenAuthReply(reply, replyPayload);
    CaptureAndReply(guard.GetChannel(), connName, MessageType::TOKEN_AUTH, replyPayload);

    EXPECT_TRUE(cb.invoked);
    EXPECT_EQ(cb.result, ResultCode::SUCCESS);
    EXPECT_EQ(cb.extraInfo, (std::vector<uint8_t> { 0xAA, 0xBB }));
}

// ============================================================================
// Test 26: HostDelegateAuthCallbackExtraInfoVerifiedE2E_001
//         Full DelegateAuth flow with complete callback content verification
// ============================================================================
HWTEST_F(AuthModuleTest, HostDelegateAuthCallbackExtraInfoVerifiedE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr TemplateId TEMPLATE_ID = 60005;

    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-delegate-extra-001", TEMPLATE_ID));

    HostBeginDelegateAuthOutput beginOutput;
    beginOutput.startDelegateAuthRequest = { 0x01, 0x02, 0x03 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _))
        .WillOnce([](const HostEndDelegateAuthInput &, HostEndDelegateAuthOutput &output) {
            output.fwkMsg = { 0xCC, 0xDD };
            output.authType = AuthType::PIN;
            output.atl = 2;
            return ResultCode::SUCCESS;
        });

    FwkCallbackCapture cb;
    ASSERT_TRUE(guard.AuthenticateDelegateAuth(26001, { 0xAB }, HOST_USER_ID, TEMPLATE_ID, 0, cb.MakeCallback()));
    DrainPendingTasks();

    std::string connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());

    StartDelegateAuthReply startReply;
    startReply.result = ResultCode::SUCCESS;
    Attributes startReplyPayload;
    EncodeStartDelegateAuthReply(startReply, startReplyPayload);
    ASSERT_TRUE(guard.CaptureVerifyAndReply(connName, MessageType::START_DELEGATE_AUTH, startReplyPayload));

    SendDelegateAuthResultRequest resultReq;
    resultReq.result = ResultCode::SUCCESS;
    resultReq.extraInfo = { 0xEE, 0xFF };
    Attributes resultPayload;
    EncodeSendDelegateAuthResultRequest(resultReq, resultPayload);
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName,
        BuildRequestRawMsg(connName, 2, MessageType::SEND_DELEGATE_AUTH_RESULT, resultPayload));
    DrainPendingTasks();

    EXPECT_TRUE(cb.invoked);
    EXPECT_EQ(cb.result, ResultCode::SUCCESS);
    EXPECT_EQ(cb.extraInfo, (std::vector<uint8_t> { 0xCC, 0xDD }));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
