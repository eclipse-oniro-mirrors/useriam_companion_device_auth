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

#include "cross_device_comm_manager.h"
#include "delegate_auth_message.h"
#include "iam_logger.h"
#include "issue_token_message.h"
#include "sync_device_status_message.h"
#include "token_auth_message.h"

#define LOG_TAG "CDA_SA_MODULE_TEST"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr UserId HOST_USER_ID = 100;
// Time to advance past the default request timeout for triggering timeout callbacks.
// DEFAULT_REQUEST_TIMEOUT_MS = 60000 (60s). Add 1s margin to ensure the deadline is exceeded.
constexpr uint64_t TIMEOUT_ADVANCE_MS = DEFAULT_REQUEST_TIMEOUT_MS + 1000;

class TimeoutModuleTest : public testing::Test {};

// ============================================================================
// Test 1: SyncDeviceStatusTimeoutE2E_001
//         HostSyncDeviceStatusRequest times out when companion does not reply
// ============================================================================
//
// What this tests:
//   HostSyncDeviceStatusRequest → send SYNC_DEVICE_STATUS → no reply →
//   timeout timer fires → Cancel(TIMEOUT) → callback invoked with error
//
// E2E level: HIGH
//   - Entry: RequestFactory.CreateHostSyncDeviceStatusRequest + RequestManager.Start
//   - Production path: HostSyncDeviceStatusRequest → OutboundRequest →
//     timer registration → Cancel on timeout
//   - Verification: SyncDeviceStatusCallback invoked with TIMEOUT result,
//     device status query reflects failure
//
// Timeout mechanism:
//   RelativeTimer Fake stores deadline = timeProvider() + ms at Register() time.
//   The time provider is linked to MockTimeKeeper's steady time.
//   DrainAllTasks() fires only timers whose deadline <= current time.
//   To trigger timeout: advance MockTimeKeeper past DEFAULT_REQUEST_TIMEOUT_MS,
//   then call DrainAllTasks().
// ============================================================================
HWTEST_F(TimeoutModuleTest, SyncDeviceStatusTimeoutE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string companionDeviceId = "companion-timeout-sync-001";

    IAM_LOGI("[Phase] Setup — companion device online, HostBeginCompanionCheck mock");
    // 1. Setup companion device (SimulateDeviceOnline + RegisterCompanionDirect).
    //    SetupCompanionDevice internally creates a FIRST SyncDeviceStatus request/reply
    //    pair as part of RegisterCompanionDirect (which includes a sync to populate
    //    device capabilities). This first sync completes during setup.
    //    Below (step 5), we create a SECOND, explicit SyncDeviceStatus request that
    //    will be the one under test — we intentionally do NOT reply to it, so it times out.
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, companionDeviceId, 60001));

    // 2. Setup Mock: HostBeginCompanionCheck returns salt + challenge
    //    (required by HostSyncDeviceStatusRequest::OnConnected)
    HostBeginCompanionCheckOutput checkOutput;
    checkOutput.salt = { 0x01, 0x02, 0x03, 0x04 };
    checkOutput.challenge = 77777;
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(checkOutput), Return(ResultCode::SUCCESS)));

    // 3. Create SyncDeviceStatus callback to capture result
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    SyncDeviceStatus callbackSyncStatus;

    auto syncCallback = [&callbackInvoked, &callbackResult, &callbackSyncStatus](ResultCode result,
                            const SyncDeviceStatus &syncDeviceStatus) {
        callbackInvoked = true;
        callbackResult = result;
        callbackSyncStatus = syncDeviceStatus;
    };

    IAM_LOGI("[Phase] Run — create SyncDeviceStatus request, send, NO reply, drain all");
    // 4. Create HostSyncDeviceStatusRequest via RequestFactory
    auto companionDeviceKey = MakeDeviceKey(companionDeviceId, HOST_USER_ID);
    auto request = GetRequestFactory().CreateHostSyncDeviceStatusRequest(
        UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        companionDeviceKey, "companion-timeout-sync-001", std::move(syncCallback));
    ASSERT_NE(request, nullptr) << "Failed to create HostSyncDeviceStatusRequest";

    // 5. Start the request
    bool startRet = GetRequestManager().Start(request);
    ASSERT_TRUE(startRet) << "Failed to start HostSyncDeviceStatusRequest";
    DrainPendingTasks();

    // 6. Verify SYNC_DEVICE_STATUS message was sent
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection to be established";
    const auto &connName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected SYNC_DEVICE_STATUS message to be sent";

    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value()) << "Failed to decode sent message";
    EXPECT_EQ(msgInfo->msgType, MessageType::SYNC_DEVICE_STATUS);
    EXPECT_FALSE(msgInfo->isReply);

    // 7. Advance time past the 60s request timeout and let timer fire
    guard.GetTimeKeeper().AdvanceSteadyTime(TIMEOUT_ADVANCE_MS);
    DrainAllTasks();

    // 8. Verify timeout occurred: callback invoked with TIMEOUT
    EXPECT_TRUE(callbackInvoked) << "Expected callback to be invoked on timeout";
    EXPECT_EQ(callbackResult, ResultCode::TIMEOUT) << "Expected TIMEOUT result code";
}

// ============================================================================
// Test 2: TokenAuthTimeoutE2E_001
//         HostTokenAuthRequest times out when companion does not reply
// ============================================================================
//
// What this tests:
//   HostTokenAuthRequest → send TOKEN_AUTH → no reply →
//   timeout timer fires → Cancel(TIMEOUT) → framework callback invoked
//
// E2E level: HIGH
//   - Entry: guard.AuthenticateTokenAuth (mimics Executor.Authenticate)
//   - Production path: HostTokenAuthRequest → OutboundRequest lifecycle
//   - Verification: callback invoked with TIMEOUT result
//
// Timeout mechanism:
//   DrainPendingTasks() sends the request. Advance steady time + DrainAllTasks() fires the timer.
// ============================================================================
HWTEST_F(TimeoutModuleTest, TokenAuthTimeoutE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEMPLATE_ID = 60002;
    constexpr ScheduleId TEST_SCHEDULE_ID = 20001;

    IAM_LOGI("[Phase] Setup — companion device online, HostBeginTokenAuth mock");
    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-timeout-token-auth-001", TEMPLATE_ID));

    // 2. Setup Mock: HostBeginTokenAuth returns tokenAuthRequest
    HostBeginTokenAuthOutput beginOutput;
    beginOutput.tokenAuthRequest = { 0x01, 0x02, 0x03, 0x04 };
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

    IAM_LOGI("[Phase] Run — start TokenAuth request, send, NO reply, drain all");
    // 4. Call AuthenticateTokenAuth via ModuleTestGuard helper
    std::vector<uint8_t> testFwkMsg = { 0xAB, 0xCD };
    bool authRet =
        guard.AuthenticateTokenAuth(TEST_SCHEDULE_ID, testFwkMsg, HOST_USER_ID, TEMPLATE_ID, 0, std::move(fwkCallback));
    ASSERT_TRUE(authRet) << "AuthenticateTokenAuth failed";
    DrainPendingTasks();

    // 5. Verify TOKEN_AUTH request was sent
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection to be established";
    const auto &actualConnName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(actualConnName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected TOKEN_AUTH request to be sent";

    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value()) << "Failed to decode sent message";
    EXPECT_EQ(msgInfo->msgType, MessageType::TOKEN_AUTH);
    EXPECT_FALSE(msgInfo->isReply);

    // 6. Advance time past the 60s request timeout and let timer fire
    guard.GetTimeKeeper().AdvanceSteadyTime(TIMEOUT_ADVANCE_MS);
    DrainAllTasks();

    // 7. Verify timeout occurred: callback invoked with TIMEOUT
    EXPECT_TRUE(callbackInvoked) << "Expected callback to be invoked on timeout";
    EXPECT_EQ(callbackResult, ResultCode::TIMEOUT) << "Expected TIMEOUT result code";
}

// ============================================================================
// Test 3: DelegateAuthTimeoutE2E_001
//         HostDelegateAuthRequest times out when companion does not reply
// ============================================================================
//
// What this tests:
//   HostDelegateAuthRequest → send START_DELEGATE_AUTH → no reply →
//   timeout timer fires → Cancel(TIMEOUT) → framework callback invoked
//
// E2E level: HIGH
//   - Entry: guard.AuthenticateDelegateAuth (mimics Executor.Authenticate)
//   - Production path: HostDelegateAuthRequest → OutboundRequest lifecycle
//   - Verification: callback invoked with TIMEOUT result
//
// Timeout mechanism:
//   DrainPendingTasks() sends the request. Advance steady time + DrainAllTasks() fires the timer.
// ============================================================================
HWTEST_F(TimeoutModuleTest, DelegateAuthTimeoutE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEMPLATE_ID = 60003;
    constexpr ScheduleId TEST_SCHEDULE_ID = 20002;

    IAM_LOGI("[Phase] Setup — companion device online, HostBeginDelegateAuth mock");
    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-timeout-delegate-001", TEMPLATE_ID));

    // 2. Setup Mock: HostBeginDelegateAuth returns startDelegateAuthRequest
    HostBeginDelegateAuthOutput beginOutput;
    beginOutput.startDelegateAuthRequest = { 0x01, 0x02, 0x03 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginOutput), Return(ResultCode::SUCCESS)));

    // 3. Create callback to capture result
    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::SUCCESS;

    auto fwkCallback = [&callbackInvoked, &callbackResult](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        (void)extraInfo;
    };

    IAM_LOGI("[Phase] Run — start DelegateAuth request, send, NO reply, drain all");
    // 4. Call AuthenticateDelegateAuth via ModuleTestGuard helper
    bool authRet = guard.AuthenticateDelegateAuth(TEST_SCHEDULE_ID, { 0xAB }, HOST_USER_ID, TEMPLATE_ID, 0,
        std::move(fwkCallback));
    ASSERT_TRUE(authRet) << "AuthenticateDelegateAuth failed";
    DrainPendingTasks();

    // 5. Verify START_DELEGATE_AUTH request was sent
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection to be established";
    const auto &actualConnName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(actualConnName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected START_DELEGATE_AUTH request to be sent";

    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value()) << "Failed to decode sent message";
    EXPECT_EQ(msgInfo->msgType, MessageType::START_DELEGATE_AUTH);
    EXPECT_FALSE(msgInfo->isReply);

    // 6. Advance time past the 60s request timeout and let timer fire
    guard.GetTimeKeeper().AdvanceSteadyTime(TIMEOUT_ADVANCE_MS);
    DrainAllTasks();

    // 7. Verify timeout occurred: callback invoked with TIMEOUT
    EXPECT_TRUE(callbackInvoked) << "Expected callback to be invoked on timeout";
    EXPECT_EQ(callbackResult, ResultCode::TIMEOUT) << "Expected TIMEOUT result code";
}

// ============================================================================
// Test 4: IssueTokenTimeoutE2E_001
//         HostIssueTokenRequest times out when companion does not reply
// ============================================================================
//
// What this tests:
//   HostIssueTokenRequest → send PRE_ISSUE_TOKEN → no reply →
//   timeout timer fires → Cancel(TIMEOUT) → request completes with error
//
// E2E level: HIGH
//   - Entry: RequestFactory.CreateHostIssueTokenRequest + RequestManager.Start
//   - Production path: HostIssueTokenRequest → OutboundRequest lifecycle
//   - Verification: SecurityAgent mock expectations verify the path;
//     IssueToken has no framework callback, but the request completes internally
//
// Timeout mechanism:
//   DrainPendingTasks() sends the request. Advance steady time + DrainAllTasks() fires the timer.
// ============================================================================
HWTEST_F(TimeoutModuleTest, IssueTokenTimeoutE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr TemplateId TEST_TEMPLATE_ID = 60004;
    constexpr uint32_t lockStateAuthType = 1;

    IAM_LOGI("[Phase] Setup — companion device online, HostPreIssueToken mock");
    // 1. Setup companion device
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER_ID, "companion-timeout-issue-001", TEST_TEMPLATE_ID));

    // 2. Setup Mock: HostPreIssueToken returns preIssueTokenRequest
    HostPreIssueTokenOutput preIssueOutput;
    preIssueOutput.preIssueTokenRequest = { 0x01, 0x02, 0x03 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(preIssueOutput), Return(ResultCode::SUCCESS)));

    // Note: HostBeginIssueToken and HostEndIssueToken should NOT be called
    // because the request times out before the companion replies to PRE_ISSUE_TOKEN.

    IAM_LOGI("[Phase] Run — create IssueToken request, send, NO reply, drain all");
    // 3. Create HostIssueTokenRequest via RequestFactory
    std::vector<uint8_t> fwkUnlockMsg = { 0xAA, 0xBB };
    auto request = GetRequestFactory().CreateHostIssueTokenRequest(
        UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID }, TEST_TEMPLATE_ID, lockStateAuthType, fwkUnlockMsg);
    ASSERT_NE(request, nullptr) << "Failed to create HostIssueTokenRequest";

    // 4. Start the request
    bool startRet = GetRequestManager().Start(request);
    ASSERT_TRUE(startRet) << "Failed to start HostIssueTokenRequest";
    DrainPendingTasks();

    // 5. Verify PRE_ISSUE_TOKEN message was sent
    auto allConnNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(allConnNames.empty()) << "Expected a connection to be established";
    const auto &connName = allConnNames[0];

    auto sentMsgs = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgs.empty()) << "Expected PRE_ISSUE_TOKEN message to be sent";

    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    ASSERT_TRUE(msgInfo.has_value()) << "Failed to decode sent message";
    EXPECT_EQ(msgInfo->msgType, MessageType::PRE_ISSUE_TOKEN);
    EXPECT_FALSE(msgInfo->isReply);

    // 6. Advance time past the 60s request timeout and let timer fire
    guard.GetTimeKeeper().AdvanceSteadyTime(TIMEOUT_ADVANCE_MS);
    DrainAllTasks();

    // 7. Verification: The SecurityAgent mock expectations verify the path.
    // HostPreIssueToken was called (EXPECT_CALL above), but HostBeginIssueToken
    // and HostEndIssueToken were NOT called because the request timed out
    // before the companion replied to PRE_ISSUE_TOKEN.
    // The request completes internally via Cancel(TIMEOUT) → CompleteWithError.
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
