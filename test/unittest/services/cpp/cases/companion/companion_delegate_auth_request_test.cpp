/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not this file except in compliance with the * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY kind, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"
#include "mock_request.h"

#include "companion_delegate_auth_request.h"
#include "delegate_auth_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

const std::string CONNECTION_NAME = "test_connection";
constexpr int32_t COMPANION_USER_ID = 200;
const DeviceKey HOST_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "host_device_id",
    .deviceUserId = 100 };
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };
const std::vector<uint8_t> START_DELEGATE_AUTH_REQUEST = { 1, 2, 3, 4 };
constexpr BindingId BINDING_ID = 1;
const HostBindingStatus HOST_BINDING_STATUS = { .bindingId = BINDING_ID };

class CompanionDelegateAuthRequestTest : public Test {
protected:
};

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillRepeatedly(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetUserAuthAdapter(), BeginDelegateAuth(_)).WillOnce(Return(12345));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillRepeatedly(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillRepeatedly(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillRepeatedly(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompanionBeginDelegateAuth_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    bool result = request->CompanionBeginDelegateAuth();

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, SecureAgentBeginDelegateAuth_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    uint64_t challenge = 0;
    Atl atl = 0;
    bool result = request->SecureAgentBeginDelegateAuth(challenge, atl);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
        .WillOnce(Invoke([](const std::string &, MessageType, const Attributes &, OnMessageReply callback) {
            SendDelegateAuthResultReply reply = { .result = ResultCode::SUCCESS };
            Attributes message;
            EncodeSendDelegateAuthResultReply(reply, message);
            callback(message);
            return true;
        }));

    ASSERT_NO_THROW(request->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo));
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_002, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    std::vector<uint8_t> badExtraInfo = { 1, 2, 3 };

    ASSERT_NO_THROW(request->HandleDelegateAuthResult(ResultCode::SUCCESS, badExtraInfo));
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_003, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo));
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_004, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    // On the failure path the request first tries SendDelegateAuthResult (SendMessage) and, since that
    // fails (resultSent_ stays false), CompleteWithError then sends REQUEST_ABORTED via SendRequestAborted
    // (a second SendMessage). Expect both calls to fail; otherwise the over-cardinality 2nd call traps.
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
        .Times(2)
        .WillOnce(Return(false))
        .WillOnce(Return(false));

    ASSERT_NO_THROW(request->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo));
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    SendDelegateAuthResultReply reply = { .result = ResultCode::SUCCESS };
    Attributes message;
    EncodeSendDelegateAuthResultReply(reply, message);

    ASSERT_NO_THROW(request->HandleSendDelegateAuthResultReply(message));
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_002, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    SendDelegateAuthResultReply reply = { .result = ResultCode::GENERAL_ERROR };
    Attributes message;
    EncodeSendDelegateAuthResultReply(reply, message);

    ASSERT_NO_THROW(request->HandleSendDelegateAuthResultReply(message));
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_003, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    Attributes badMessage;

    ASSERT_NO_THROW(request->HandleSendDelegateAuthResultReply(badMessage));
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);
    request->contextId_ = 12345;

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);
    request->contextId_ = std::nullopt;

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_003, TestSize.Level0)
{
    // needEndDelegateAuth_ = true, contextId_ = nullopt
    // Should call SecurityAgentEndDelegateAuth for cleanup
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);
    request->needEndDelegateAuth_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_004, TestSize.Level0)
{
    // needEndDelegateAuth_ = true AND contextId_ set
    // Should cancel auth context AND call SecurityAgentEndDelegateAuth for cleanup
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);
    request->contextId_ = 12345;
    request->needEndDelegateAuth_ = true;

    EXPECT_CALL(guard.GetUserAuthAdapter(), CancelAuthentication(_)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_005, TestSize.Level0)
{
    // needEndDelegateAuth_ = true, SecurityAgentEndDelegateAuth returns error
    // Should still complete without crash
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);
    request->needEndDelegateAuth_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_AbortsHostWhenResultNotSent, TestSize.Level0)
{
    // OnStart/mid-flow failure: the host is still waiting for SEND_DELEGATE_AUTH_RESULT while the START_DELEGATE_AUTH
    // reply was already answered SUCCESS by the handler (RequestManager::Start returns before OnStart runs).
    // CompleteWithError must emit REQUEST_ABORTED so the host aborts promptly instead of hanging until the 60s
    // timeout.
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    bool abortedSent = false;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::REQUEST_ABORTED, _, _))
        .WillOnce(Invoke([&abortedSent](const std::string &, MessageType, const Attributes &, OnMessageReply) {
            abortedSent = true;
            return true;
        }));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
    EXPECT_TRUE(abortedSent);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_DoesNotAbortAfterResultSent, TestSize.Level0)
{
    // Once SEND_DELEGATE_AUTH_RESULT was delivered the host already knows the outcome; CompleteWithError must not
    // emit a second REQUEST_ABORTED (resultSent_ guard).
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    int abortCount = 0;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
        .WillRepeatedly(
            Invoke([&abortCount](const std::string &, MessageType type, const Attributes &, OnMessageReply) {
                if (type == MessageType::REQUEST_ABORTED) {
                    abortCount++;
                }
                return true;
            }));

    // Deliver the result first -> resultSent_ becomes true.
    ASSERT_TRUE(request->SendDelegateAuthResult(ResultCode::SUCCESS, {}));
    // Subsequent error completion must not notify the host again.
    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));

    EXPECT_EQ(abortCount, 0);
}

HWTEST_F(CompanionDelegateAuthRequestTest, Cancel_AbortsHostExactlyOnce, TestSize.Level0)
{
    // Cancel() (60s timeout / same-device preemption) already emits REQUEST_ABORTED via InboundRequest::Cancel.
    // CompleteWithError must not emit a second one (no double-abort regression).
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    int abortCount = 0;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::REQUEST_ABORTED, _, _))
        .WillRepeatedly(Invoke([&abortCount](const std::string &, MessageType, const Attributes &, OnMessageReply) {
            abortCount++;
            return true;
        }));

    ASSERT_TRUE(request->Cancel(ResultCode::GENERAL_ERROR));
    EXPECT_EQ(abortCount, 1);
}

HWTEST_F(CompanionDelegateAuthRequestTest, Cancel_DoesNotAbortAfterCompletion, TestSize.Level0)
{
    // A late Cancel (e.g. the 60s timeout firing after the request already delivered its result and succeeded) must
    // not emit a second REQUEST_ABORTED. Symmetric to CompleteWithError_DoesNotAbortAfterResultSent; exercises the
    // InboundRequest::Cancel guard on both completed_ and resultSent_.
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    int abortCount = 0;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
        .WillRepeatedly(
            Invoke([&abortCount](const std::string &, MessageType type, const Attributes &, OnMessageReply) {
                if (type == MessageType::REQUEST_ABORTED) {
                    abortCount++;
                }
                return true;
            }));

    // Deliver the result first -> resultSent_ becomes true; then succeed -> completed_ becomes true.
    ASSERT_TRUE(request->SendDelegateAuthResult(ResultCode::SUCCESS, {}));
    request->CompleteWithSuccess();
    // A subsequent late Cancel must not notify the host again.
    ASSERT_TRUE(request->Cancel(ResultCode::TIMEOUT));

    EXPECT_EQ(abortCount, 0);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    ASSERT_NO_THROW(request->CompleteWithSuccess());
}

HWTEST_F(CompanionDelegateAuthRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(CompanionDelegateAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    EXPECT_EQ(request->GetMaxConcurrency(), 1);
}

HWTEST_F(CompanionDelegateAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    // Different device (nullopt) should not preempt
    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_DELEGATE_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);

    // Same device should preempt
    auto newRequest2 = std::make_shared<MockIRequest>(RequestType::COMPANION_DELEGATE_AUTH_REQUEST);
    newRequest2->SetPeerDeviceKey(HOST_DEVICE_KEY);
    result = request->ShouldCancelOnNewRequest(*newRequest2, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_005, TestSize.Level0)
{
    MockGuard guard;

    CompanionDelegateAuthParam delegateAuthParam = { .remoteTokenId = 0 };
    auto request = std::make_shared<CompanionDelegateAuthRequest>(CONNECTION_NAME, COMPANION_USER_ID, HOST_DEVICE_KEY,
        START_DELEGATE_AUTH_REQUEST, delegateAuthParam);

    DeviceKey wrongDeviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "wrong_device_id",
        .deviceUserId = 999 };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillRepeatedly(Return(std::make_optional(wrongDeviceKey)));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
