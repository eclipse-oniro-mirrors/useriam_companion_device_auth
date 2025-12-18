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

#include "companion_issue_token_request.h"
#include "issue_token_message.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

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
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto hostBindingMgr =
            std::shared_ptr<IHostBindingManager>(&mockHostBindingManager_, [](IHostBindingManager *) {});
        SingletonManager::GetInstance().SetHostBindingManager(hostBindingMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        PreIssueTokenRequest preRequest = { .hostDeviceKey = hostDeviceKey_,
            .companionUserId = companionUserId_,
            .extraInfo = { 1, 2, 3 } };
        EncodePreIssueTokenRequest(preRequest, preIssueTokenRequest_);
        preIssueTokenRequest_.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
            static_cast<int32_t>(preRequest.hostDeviceKey.idType));
        preIssueTokenRequest_.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, preRequest.hostDeviceKey.deviceId);

        ON_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
            .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
        ON_CALL(mockHostBindingManager_, SetHostBindingTokenValid(_, _)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceStatus()).WillByDefault(Return(localDeviceStatus_));
        ON_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
            .WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeLocalDeviceStatus(_))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockSecurityAgent_, CompanionPreIssueToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, CompanionCancelIssueToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, CompanionProcessIssueToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    }

    void TearDown() override
    {
        request_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

    void CreateDefaultRequest()
    {
        request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
            hostDeviceKey_);
    }

protected:
    std::shared_ptr<CompanionIssueTokenRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;

    std::string connectionName_ = "test_connection";
    Attributes preIssueTokenRequest_;
    OnMessageReply replyCallback_ = [](const Attributes &reply) {};
    int32_t companionUserId_ = 200;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    HostBindingStatus hostBindingStatus_;
    LocalDeviceStatus localDeviceStatus_ = { .isAuthMaintainActive = true };
};

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_001, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreIssueTokenReply preIssueTokenReply;
        EXPECT_TRUE(DecodePreIssueTokenReply(reply, preIssueTokenReply));
        receivedResult = static_cast<int32_t>(preIssueTokenReply.result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceStatus()).WillOnce(Return(localDeviceStatus_));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeLocalDeviceStatus(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockSecurityAgent_, CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _)).WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_002, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreIssueTokenReply preIssueTokenReply;
        EXPECT_TRUE(DecodePreIssueTokenReply(reply, preIssueTokenReply));
        receivedResult = static_cast<int32_t>(preIssueTokenReply.result);
    };

    Attributes emptyRequest;
    request_ =
        std::make_shared<CompanionIssueTokenRequest>(connectionName_, emptyRequest, replyCallback_, DeviceKey {});

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceStatus()).WillOnce(Return(localDeviceStatus_));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeLocalDeviceStatus(_))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_003, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreIssueTokenReply preIssueTokenReply;
        EXPECT_TRUE(DecodePreIssueTokenReply(reply, preIssueTokenReply));
        receivedResult = static_cast<int32_t>(preIssueTokenReply.result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceStatus()).WillOnce(Return(localDeviceStatus_));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeLocalDeviceStatus(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_004, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreIssueTokenReply preIssueTokenReply;
        EXPECT_TRUE(DecodePreIssueTokenReply(reply, preIssueTokenReply));
        receivedResult = static_cast<int32_t>(preIssueTokenReply.result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceStatus()).WillOnce(Return(localDeviceStatus_));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeLocalDeviceStatus(_))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockSecurityAgent_, CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_FALSE(replyCalled);
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_005, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreIssueTokenReply preIssueTokenReply;
        EXPECT_TRUE(DecodePreIssueTokenReply(reply, preIssueTokenReply));
        receivedResult = static_cast<int32_t>(preIssueTokenReply.result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    LocalDeviceStatus localDeviceStatus = { .isAuthMaintainActive = false };
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceStatus()).WillOnce(Return(localDeviceStatus));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, OnStart_006, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    replyCallback_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreIssueTokenReply preIssueTokenReply;
        EXPECT_TRUE(DecodePreIssueTokenReply(reply, preIssueTokenReply));
        receivedResult = static_cast<int32_t>(preIssueTokenReply.result);
    };

    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, preIssueTokenRequest_, replyCallback_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceStatus()).WillOnce(Return(localDeviceStatus_));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeLocalDeviceStatus(_)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_001, TestSize.Level0)
{
    Attributes badRequest;
    request_ = std::make_shared<CompanionIssueTokenRequest>(connectionName_, badRequest, replyCallback_, DeviceKey {});

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_002, TestSize.Level0)
{
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
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_004, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _)).WillOnce(Return(nullopt));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompanionPreIssueToken_005, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockSecurityAgent_, CompanionPreIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    std::vector<uint8_t> preIssueTokenReply;
    bool result = request_->CompanionPreIssueToken(preIssueTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_001, TestSize.Level0)
{
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
        IssueTokenReply issueTokenReply;
        EXPECT_TRUE(DecodeIssueTokenReply(reply, issueTokenReply));
        receivedResult = static_cast<int32_t>(issueTokenReply.result);
    };

    EXPECT_CALL(mockSecurityAgent_, CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockHostBindingManager_, SetHostBindingTokenValid(_, _)).WillOnce(Return(true));

    request_->HandleIssueTokenMessage(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_002, TestSize.Level0)
{
    CreateDefaultRequest();

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        IssueTokenReply issueTokenReply;
        EXPECT_TRUE(DecodeIssueTokenReply(reply, issueTokenReply));
        receivedResult = static_cast<int32_t>(issueTokenReply.result);
    };

    Attributes badRequest;
    request_->HandleIssueTokenMessage(badRequest, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_003, TestSize.Level0)
{
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
        IssueTokenReply issueTokenReply;
        EXPECT_TRUE(DecodeIssueTokenReply(reply, issueTokenReply));
        receivedResult = static_cast<int32_t>(issueTokenReply.result);
    };

    EXPECT_CALL(mockSecurityAgent_, CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleIssueTokenMessage(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionIssueTokenRequestTest, HandleIssueTokenMessage_004, TestSize.Level0)
{
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
        IssueTokenReply issueTokenReply;
        EXPECT_TRUE(DecodeIssueTokenReply(reply, issueTokenReply));
        receivedResult = static_cast<int32_t>(issueTokenReply.result);
    };

    EXPECT_CALL(mockSecurityAgent_, CompanionProcessIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockHostBindingManager_, SetHostBindingTokenValid(_, _)).WillOnce(Return(false));

    request_->HandleIssueTokenMessage(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = true;

    EXPECT_CALL(mockSecurityAgent_, CompanionCancelIssueToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = true;

    EXPECT_CALL(mockSecurityAgent_, CompanionCancelIssueToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionIssueTokenRequestTest, CompleteWithError_003, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = false;

    EXPECT_CALL(mockSecurityAgent_, CompanionCancelIssueToken(_)).Times(0);

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionIssueTokenRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
