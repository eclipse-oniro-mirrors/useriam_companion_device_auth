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
#include "service_common.h"
#include "singleton_manager.h"

#include "iam_logger.h"
#include "token_auth_message.h"

#define LOG_TAG "CDA_SA_MODULE_TEST"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class ConnectionModuleTest : public testing::Test {};

// Common test constants
constexpr UserId HOST_USER_ID = 100;

// ============================================================================
// Test 1: RemoteDisconnectCancelsRequestE2E_001
//         Remote device disconnects during active TokenAuth request ->
//         OutboundRequest is canceled via connection loss notification
// ============================================================================
//
// What this tests:
//   OutboundRequest (HostTokenAuthRequest) in flight -> remote disconnect
//   -> ConnectionManager.HandleChannelConnectionClosed -> NotifyConnectionStatus(DISCONNECTED)
//   -> MessageRouter.HandleConnectionDown -> pending reply erased -> connection removed
//   -> OutboundRequest CompleteWithError via timeout or explicit cancel
//
// E2E level: HIGH
//   - Entry: TestSimulateRemoteDisconnect at FakeChannel boundary
//   - Production path: ConnectionManager -> MessageRouter -> OutboundRequest cleanup
//   - Verification: callback invoked with error result (connection lost)
// ============================================================================
HWTEST_F(ConnectionModuleTest, RemoteDisconnectCancelsRequestE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    IAM_LOGI("[Phase] Setup -- companion device online, HostBeginTokenAuth mock");
    // 1. Setup companion device for connection
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-disconnect-remote-001", 61001));

    // 2. Setup Mock: HostBeginTokenAuth returns tokenAuthRequest
    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02, 0x03 };
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

    IAM_LOGI("[Phase] Run -- remote disconnect during active request");
    // 4. Call AuthenticateTokenAuth via ModuleTestGuard helper (mimics Executor.Authenticate())
    constexpr ScheduleId TEST_SCHEDULE_ID = 6001;
    constexpr TemplateId TEST_TEMPLATE_ID = 61001;
    std::vector<uint8_t> testFwkMsg = { 0xAB, 0xCD };

    bool authRet = guard.AuthenticateTokenAuth(TEST_SCHEDULE_ID, testFwkMsg, HOST_USER_ID, TEST_TEMPLATE_ID, 0,
        std::move(fwkCallback));
    ASSERT_TRUE(authRet) << "AuthenticateTokenAuth failed";
    DrainPendingTasks();

    // 5. Get connection name and verify TOKEN_AUTH message was sent
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection to be established";
    const auto &connName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected TOKEN_AUTH message to be sent";

    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value()) << "Failed to decode TOKEN_AUTH message";
    EXPECT_EQ(msgInfo->msgType, MessageType::TOKEN_AUTH);

    // 6. Simulate remote disconnect
    guard.GetChannel().TestSimulateRemoteDisconnect(connName, "remote device disconnected");
    DrainPendingTasks();

    // 7. Verify: callback invoked with COMMUNICATION_ERROR (connection loss triggers
    //    OutboundRequest::HandleConnectionStatus(DISCONNECTED) → CompleteWithError(COMMUNICATION_ERROR))
    EXPECT_TRUE(callbackInvoked) << "Expected callback to be invoked on remote disconnect";
    EXPECT_EQ(callbackResult, ResultCode::COMMUNICATION_ERROR) << "Expected COMMUNICATION_ERROR on disconnect";
}

// ============================================================================
// Test 2: DisconnectMessageHandlingE2E_001
//         Remote peer sends DISCONNECT message -> ConnectionManager closes connection
//         -> active OutboundRequest is canceled
// ============================================================================
//
// What this tests:
//   Host sends TokenAuth request -> Companion replies with DISCONNECT notification
//   -> MessageRouter.HandleRequest detects MessageType::DISCONNECT
//   -> channel->OnRemoteDisconnect -> ConnectionManager.HandleChannelConnectionClosed
//   -> pending reply erased -> OutboundRequest CompleteWithError
//
// E2E level: HIGH
//   - Entry: raw DISCONNECT message injection at FakeChannel boundary
//   - Production path: MessageRouter.HandleRequest -> DISCONNECT handling -> channel->OnRemoteDisconnect
//   - Verification: callback invoked with error result
// ============================================================================
HWTEST_F(ConnectionModuleTest, DisconnectMessageHandlingE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    IAM_LOGI("[Phase] Setup -- companion device online, HostBeginTokenAuth mock");
    // 1. Setup companion device for connection
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-disconnect-msg-001", 62001));

    // 2. Setup Mock: HostBeginTokenAuth returns tokenAuthRequest
    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02, 0x03 };
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

    IAM_LOGI("[Phase] Run -- DISCONNECT message during active request");
    // 4. Call AuthenticateTokenAuth via ModuleTestGuard helper (mimics Executor.Authenticate())
    constexpr ScheduleId TEST_SCHEDULE_ID = 6002;
    constexpr TemplateId TEST_TEMPLATE_ID = 62001;
    std::vector<uint8_t> testFwkMsg = { 0xDE, 0xAD };

    bool authRet = guard.AuthenticateTokenAuth(TEST_SCHEDULE_ID, testFwkMsg, HOST_USER_ID, TEST_TEMPLATE_ID, 0,
        std::move(fwkCallback));
    ASSERT_TRUE(authRet) << "AuthenticateTokenAuth failed";
    DrainPendingTasks();

    // 5. Get connection name and verify TOKEN_AUTH message was sent
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection to be established";
    const auto &connName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected TOKEN_AUTH message to be sent";

    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value()) << "Failed to decode TOKEN_AUTH message";
    EXPECT_EQ(msgInfo->msgType, MessageType::TOKEN_AUTH);

    // 6. Build DISCONNECT raw message and inject it
    //    DISCONNECT is a notification: MessageType::DISCONNECT with ATTR_CDA_SA_REASON.
    //    MessageRouter.HandleRequest detects DISCONNECT type and calls
    //    channel->OnRemoteDisconnect which triggers the disconnect callback chain.
    Attributes disconnectPayload;
    disconnectPayload.SetStringValue(Attributes::ATTR_CDA_SA_REASON, "user logout");
    auto disconnectRawMsg = BuildRequestRawMsg(connName, 1, MessageType::DISCONNECT, disconnectPayload);

    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, disconnectRawMsg);
    DrainPendingTasks();

    // 7. Verify: callback invoked with COMMUNICATION_ERROR (DISCONNECT message triggers
    //    OnRemoteDisconnect → HandleChannelConnectionClosed → NotifyConnectionStatus(DISCONNECTED)
    //    → OutboundRequest::HandleConnectionStatus(DISCONNECTED) → CompleteWithError(COMMUNICATION_ERROR))
    EXPECT_TRUE(callbackInvoked) << "Expected callback to be invoked when DISCONNECT received";
    EXPECT_EQ(callbackResult, ResultCode::COMMUNICATION_ERROR) << "Expected COMMUNICATION_ERROR on DISCONNECT";
}

// ============================================================================
// Test 3: KeepAliveAfterIdleE2E_001
//         Connection idle for >10s -> ConnectionManager sends KEEP_ALIVE ->
//         Companion replies with SUCCESS -> connection refreshes activity time
// ============================================================================
//
// What this tests:
//   Connection established and idle -> periodic HandleIdleMonitorTimer fires
//   -> detects idle time >= CONNECTION_IDLE_TIMEOUT_MS (10s) -> sends KEEP_ALIVE
//   -> companion KeepAliveHandler replies SUCCESS -> HandleKeepAliveReply refreshes
//   lastActivityTimeMs -> connection survives
//
// E2E level: HIGH
//   - Entry: time advancement triggers periodic timer via DrainAllTasks
//   - Production path: ConnectionManager.HandleIdleMonitorTimer ->
//     MessageRouter.SendMessage(KEEP_ALIVE) -> KeepAliveHandler -> HandleKeepAliveReply
//   - Verification: KEEP_ALIVE message sent, SUCCESS reply keeps connection alive
// ============================================================================
HWTEST_F(ConnectionModuleTest, KeepAliveAfterIdleE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr TemplateId TEST_TEMPLATE_ID = 63001;

    HostBeginCompanionCheckOutput checkOutput;
    checkOutput.salt = { 0x05, 0x06, 0x07, 0x08 };
    checkOutput.challenge = 54321;
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(checkOutput), Return(ResultCode::SUCCESS)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndCompanionCheck(_)).WillRepeatedly(Return(ResultCode::SUCCESS));

    // Setup: register companion device (establishes connection and syncs)
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-keepalive-001", TEST_TEMPLATE_ID));

    // Setup: create outbound TokenAuth request to establish a real connection
    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    FwkCallbackCapture cb;
    ASSERT_TRUE(guard.AuthenticateTokenAuth(6003, { 0xAB }, HOST_USER_ID, TEST_TEMPLATE_ID, 0, cb.MakeCallback()));
    DrainPendingTasks();

    std::string connName = guard.GetAnyConnectionName();
    ASSERT_FALSE(connName.empty());
    auto msgInfo = guard.CaptureOutboundMessage(connName, MessageType::TOKEN_AUTH);
    ASSERT_TRUE(msgInfo.has_value());

    // Run: advance steady time past CONNECTION_IDLE_TIMEOUT_MS(10000) to trigger KeepAlive.
    // Step A: advance 4999ms — well under MESSAGE_TIMEOUT_MS(10000), idle timer not yet due
    guard.GetChannel().ClearSentMessages();
    guard.GetTimeKeeper().AdvanceSteadyTime(4999);
    DrainAllTasks();
    // Step B: advance 6002ms (total=11001ms) — exceeds CONNECTION_IDLE_TIMEOUT_MS(10000)
    guard.GetTimeKeeper().AdvanceSteadyTime(6002);
    DrainAllTasks();

    // Find KEEP_ALIVE message
    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty());
    uint32_t keepAliveSeq = 0;
    bool keepAliveFound = false;
    for (const auto &rawMsg : sentMsgs) {
        auto info = DecodeRawMsg(rawMsg);
        if (info && info->msgType == MessageType::KEEP_ALIVE && !info->isReply) {
            keepAliveSeq = info->seq;
            keepAliveFound = true;
            break;
        }
    }
    EXPECT_TRUE(keepAliveFound);

    // Inject KeepAlive SUCCESS reply → HandleKeepAliveReply refreshes lastActivityTimeMs
    // → connection survives (not closed by idle timeout)
    Attributes keepAliveReplyPayload;
    keepAliveReplyPayload.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName,
        BuildReplyRawMsg(connName, keepAliveSeq, MessageType::KEEP_ALIVE, keepAliveReplyPayload));
    DrainPendingTasks();

    EXPECT_TRUE(GetCrossDeviceCommManager().IsConnectionOpen(connName));
    EXPECT_FALSE(cb.invoked);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
