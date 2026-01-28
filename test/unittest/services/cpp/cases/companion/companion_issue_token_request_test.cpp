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

#include "mock_guard.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "companion_issue_token_request.h"
#include "issue_token_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class CompanionIssueTokenRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
            hostDeviceKey_);
    }

protected:
    std::shared_ptr<CompanionIssueTokenRequest> request_;
    std::string connectionName_ = "test_connection";
    Attributes preIssueTokenRequest_;
    OnMessageReply replyCallback_ = [](const Attributes &reply) {};
    int32_t companionUserId_ = 200;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    HostBindingStatus hostBindingStatus_;
};

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    Attributes emptyRequest;
    request_ =
        std::make_shared<CompanionIssueTokenRequest>(connectionName_, emptyRequest, replyCallback_, DeviceKey {});

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_FALSE(replyCalled);
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_005, TestSize.Level0)
{
    MockGuard guard;
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_006, TestSize.Level0)
{
    MockGuard guard;
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodePreIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_001, TestSize.Level0)
{
    MockGuard guard;
    Attributes badRequest;
    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, badRequest, replyCallback_, DeviceKey {});

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_002, TestSize.Level0)
{
    MockGuard guard;
    // Create request with a different peer device key to trigger mismatch
    DeviceKey differentDeviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "different_device_id",
        .deviceUserId = 100 };
    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        differentDeviceKey);

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_004, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_005, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    IssueTokenRequest issueRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = { 1, 2, 3 } };
    Attributes request;
    EncodeIssueTokenRequest(issueRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(issueRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, issueRequest.hostDeviceKey.deviceId);

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodeIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetHostBindingManager(), SetHostBindingTokenValid(_, _)).WillOnce(Return(true));

    request_->HandleIssueTokenMessage(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodeIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    Attributes badRequest;
    request_->HandleIssueTokenMessage(badRequest, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    IssueTokenRequest issueRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = { 1, 2, 3 } };
    Attributes request;
    EncodeIssueTokenRequest(issueRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(issueRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, issueRequest.hostDeviceKey.deviceId);

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodeIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleIssueTokenMessage(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_004, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    IssueTokenRequest issueRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = { 1, 2, 3 } };
    Attributes request;
    EncodeIssueTokenRequest(issueRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(issueRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, issueRequest.hostDeviceKey.deviceId);

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto result = DecodeIssueTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        receivedResult = static_cast<int32_t>(result.value().result);
    };

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetHostBindingManager(), SetHostBindingTokenValid(_, _)).WillOnce(Return(false));

    request_->HandleIssueTokenMessage(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelIssueToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelIssueToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = false;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelIssueToken(_)).Times(0);

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionIssueTokenRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(CompanionIssueTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(CompanionIssueTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->peerDeviceKey_ = std::nullopt;

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ISSUE_TOKEN_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleAuthMaintainActiveChanged_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    request_->HandleAuthMaintainActiveChanged(true);
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleAuthMaintainActiveChanged_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    request_->HandleAuthMaintainActiveChanged(false);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
