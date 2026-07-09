/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"
#include "mock_request.h"

#include "common_message.h"
#include "companion_issue_token_request.h"
#include "issue_token_message.h"

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
    .deviceUserId = COMPANION_USER_ID };
const HostBindingStatus HOST_BINDING_STATUS = {};

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

Attributes MakePreIssueTokenRequest()
{
    Attributes attrs;
    EncodeHostDeviceKey(HOST_DEVICE_KEY, attrs);
    // SRC_IDENTIFIER / SRC_IDENTIFIER_TYPE are decode-only: the message router fills them on
    // receive from the authenticated connection, so EncodeHostDeviceKey no longer sets them.
    // Emulate the router here so the round-trip decode in OnStart recovers the host device key.
    attrs.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(HOST_DEVICE_KEY.idType));
    attrs.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, HOST_DEVICE_KEY.deviceId);
    PreIssueTokenRequest preIssueRequest = { .hostDeviceKey = HOST_DEVICE_KEY,
        .companionUserId = COMPANION_USER_ID,
        .extraInfo = { 1, 2, 3 } };
    EncodePreIssueTokenRequest(preIssueRequest, attrs);
    return attrs;
}

class CompanionIssueTokenRequestTest : public Test {
protected:
};

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply replyCallback = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_TRUE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply replyCallback = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    Attributes emptyRequest;
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, emptyRequest, std::move(replyCallback),
        DeviceKey {});

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply replyCallback = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply replyCallback = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
    // Subscribe failure must still notify the host via PreIssueTokenReply, otherwise the host waits for the
    // PRE_ISSUE_TOKEN reply until the 60s timeout.
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::COMMUNICATION_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_005, TestSize.Level0)
{
    MockGuard guard;
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply replyCallback = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    Attributes attrs;
    auto request =
        std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, attrs, std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_006, TestSize.Level0)
{
    MockGuard guard;
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply replyCallback = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    Attributes attrs;
    auto request =
        std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, attrs, std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_001, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    Attributes badRequest;
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, badRequest, std::move(replyCallback),
        DeviceKey {});

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_002, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    // Create request with a different peer device key to trigger mismatch
    DeviceKey differentDeviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "different_device_id",
        .deviceUserId = 100 };
    // Populate preIssueTokenRequest with valid data (with HOST_DEVICE_KEY, not differentDeviceKey)
    Attributes attrs;
    PreIssueTokenRequest preIssueRequest = { .hostDeviceKey = HOST_DEVICE_KEY,
        .companionUserId = COMPANION_USER_ID,
        .extraInfo = { 1, 2, 3 } };
    EncodePreIssueTokenRequest(preIssueRequest, attrs);
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, attrs, std::move(replyCallback),
        differentDeviceKey);

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_005, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleAuthMaintainActiveChanged_AbortsHostOnInactive, TestSize.Level0)
{
    // After OnStart replies PreIssueTokenReply(SUCCESS), the host waits for ISSUE_TOKEN. If local auth-maintain
    // drops, the request must Cancel() so REQUEST_ABORTED reaches the host (the host's OutboundRequest subscribes
    // to it during OpenConnection); a bare CompleteWithError would leave the host hanging until the 60s timeout.
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    OnMessageReply replyCallback = [](const Attributes &) {};
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, MakePreIssueTokenRequest(),
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    bool abortedSent = false;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::REQUEST_ABORTED, _, _))
        .WillOnce(Invoke([&abortedSent](const std::string &, MessageType, const Attributes &, OnMessageReply) {
            abortedSent = true;
            return true;
        }));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelIssueToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    ASSERT_NO_THROW(request->HandleAuthMaintainActiveChanged(false));
    EXPECT_TRUE(abortedSent);
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    IssueTokenRequest issueRequest = { .hostDeviceKey = HOST_DEVICE_KEY,
        .companionUserId = COMPANION_USER_ID,
        .extraInfo = { 1, 2, 3 } };
    Attributes attrs;
    EncodeIssueTokenRequest(issueRequest, attrs);
    attrs.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(issueRequest.hostDeviceKey.idType));
    attrs.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, issueRequest.hostDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodeIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetHostBindingManager(), SetHostBindingTokenValid(_, _)).WillOnce(Return(true));

    request->HandleIssueTokenMessage(attrs, onMessageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodeIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    Attributes badRequest;
    request->HandleIssueTokenMessage(badRequest, onMessageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    IssueTokenRequest issueRequest = { .hostDeviceKey = HOST_DEVICE_KEY,
        .companionUserId = COMPANION_USER_ID,
        .extraInfo = { 1, 2, 3 } };
    Attributes attrs;
    EncodeIssueTokenRequest(issueRequest, attrs);
    attrs.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(issueRequest.hostDeviceKey.idType));
    attrs.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, issueRequest.hostDeviceKey.deviceId);

    // Count replies: the failure path must invoke onMessageReply exactly once. Regression guard against the old
    // double-send where a manual onMessageReply plus the errorGuard destructor emitted two failure replies.
    auto replyCount = std::make_shared<int>(0);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [replyCount, receivedResult](const Attributes &reply) {
        (*replyCount)++;
        auto result = DecodeIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandleIssueTokenMessage(attrs, onMessageReply);

    EXPECT_EQ(*replyCount, 1);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    IssueTokenRequest issueRequest = { .hostDeviceKey = HOST_DEVICE_KEY,
        .companionUserId = COMPANION_USER_ID,
        .extraInfo = { 1, 2, 3 } };
    Attributes attrs;
    EncodeIssueTokenRequest(issueRequest, attrs);
    attrs.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(issueRequest.hostDeviceKey.idType));
    attrs.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, issueRequest.hostDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto result = DecodeIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        *receivedResult = static_cast<int32_t>(result.value().result);
    };

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetHostBindingManager(), SetHostBindingTokenValid(_, _)).WillOnce(Return(false));

    request->HandleIssueTokenMessage(attrs, onMessageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);
    request->needCancelIssueToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelIssueToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);
    request->needCancelIssueToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelIssueToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_003, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);
    request->needCancelIssueToken_ = false;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelIssueToken(_)).Times(0);

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(CompanionIssueTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    EXPECT_EQ(request->GetMaxConcurrency(), 10);
}

HWTEST_F(CompanionIssueTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    // std::nullopt doesn't match any device, so shouldn't cancel
    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ISSUE_TOKEN_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleAuthMaintainActiveChanged_001, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    ASSERT_NO_THROW(request->HandleAuthMaintainActiveChanged(true));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleAuthMaintainActiveChanged_002, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    ASSERT_NO_THROW(request->HandleAuthMaintainActiveChanged(false));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_006, TestSize.Level0)
{
    MockGuard guard;

    DeviceKey wrongDeviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "wrong_device_id",
        .deviceUserId = 999 };
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(wrongDeviceKey)));

    OnMessageReply replyCallback = [](const Attributes &reply) {};
    auto preIssueTokenRequest = MakePreIssueTokenRequest();
    auto request = std::make_shared<CompanionIssueTokenRequest>(CONNECTION_NAME, preIssueTokenRequest,
        std::move(replyCallback), HOST_DEVICE_KEY);

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
