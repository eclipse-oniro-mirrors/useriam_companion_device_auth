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

#include "host_obtain_token_request.h"
#include "obtain_token_message.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_user_id_manager.h"

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

class HostObtainTokenRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto activeUserMgr = std::shared_ptr<IUserIdManager>(&mockActiveUserIdManager_, [](IUserIdManager *) {});
        SingletonManager::GetInstance().SetActiveUserIdManager(activeUserMgr);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        PreObtainTokenRequest preRequest = { .hostUserId = 100,
            .companionDeviceKey = companionDeviceKey_,
            .extraInfo = { 1, 2, 3 } };
        EncodePreObtainTokenRequest(preRequest, preObtainTokenRequest_);
        preObtainTokenRequest_.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
            static_cast<int32_t>(preRequest.companionDeviceKey.idType));
        preObtainTokenRequest_.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER,
            preRequest.companionDeviceKey.deviceId);

        ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
            .WillByDefault(Return(std::make_optional(companionStatus_)));
        ON_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
            .WillByDefault(Return(std::make_optional(SecureProtocolId::DEFAULT)));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_))
            .WillByDefault(Return(
                std::make_optional(DeviceStatus { .deviceKey = companionDeviceKey_, .isAuthMaintainActive = true })));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockSecurityAgent_, HostProcessPreObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostProcessObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
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
        request_ = std::make_shared<HostObtainTokenRequest>(connectionName_, preObtainTokenRequest_, onMessageReply_,
            companionDeviceKey_);
    }

protected:
    std::shared_ptr<HostObtainTokenRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockUserIdManager> mockActiveUserIdManager_;
    NiceMock<MockMiscManager> mockMiscManager_;

    std::string connectionName_ = "test_connection";
    Attributes preObtainTokenRequest_;
    OnMessageReply onMessageReply_ = [](const Attributes &) {};
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    CompanionStatus companionStatus_;
};

HWTEST_F(HostObtainTokenRequestTest, OnStart_001, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    onMessageReply_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreObtainTokenReply preObtainTokenReply;
        auto result = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        preObtainTokenReply = result.value();
        receivedResult = preObtainTokenReply.result;
    };

    request_ = std::make_shared<HostObtainTokenRequest>(connectionName_, preObtainTokenRequest_, onMessageReply_,
        companionDeviceKey_);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(mockSecurityAgent_, HostProcessPreObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _)).WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_002, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    onMessageReply_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreObtainTokenReply preObtainTokenReply;
        auto result = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        preObtainTokenReply = result.value();
        receivedResult = preObtainTokenReply.result;
    };

    Attributes emptyRequest;
    request_ = std::make_shared<HostObtainTokenRequest>(connectionName_, emptyRequest, onMessageReply_, DeviceKey {});

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_003, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    onMessageReply_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreObtainTokenReply preObtainTokenReply;
        auto result = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        preObtainTokenReply = result.value();
        receivedResult = preObtainTokenReply.result;
    };

    request_ = std::make_shared<HostObtainTokenRequest>(connectionName_, preObtainTokenRequest_, onMessageReply_,
        companionDeviceKey_);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_004, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    onMessageReply_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreObtainTokenReply preObtainTokenReply;
        auto result = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        preObtainTokenReply = result.value();
        receivedResult = preObtainTokenReply.result;
    };

    request_ = std::make_shared<HostObtainTokenRequest>(connectionName_, preObtainTokenRequest_, onMessageReply_,
        companionDeviceKey_);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_005, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    onMessageReply_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreObtainTokenReply preObtainTokenReply;
        auto result = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        preObtainTokenReply = result.value();
        receivedResult = preObtainTokenReply.result;
    };

    request_ = std::make_shared<HostObtainTokenRequest>(connectionName_, preObtainTokenRequest_, onMessageReply_,
        companionDeviceKey_);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(mockSecurityAgent_, HostProcessPreObtainToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_006, TestSize.Level0)
{
    bool replyCalled = false;
    int32_t receivedResult = -1;
    onMessageReply_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        PreObtainTokenReply preObtainTokenReply;
        auto result = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(result.has_value());
        preObtainTokenReply = result.value();
        receivedResult = preObtainTokenReply.result;
    };

    request_ = std::make_shared<HostObtainTokenRequest>(connectionName_, preObtainTokenRequest_, onMessageReply_,
        companionDeviceKey_);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(mockSecurityAgent_, HostProcessPreObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_001, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    Attributes request;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 100,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = companionDeviceKey_ };
    EncodeObtainTokenRequest(obtainTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, receivedResult));
    };

    EXPECT_CALL(mockSecurityAgent_, HostProcessObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCompanionManager_, SetCompanionTokenAtl(_, _)).WillOnce(Return(true));

    request_->HandleObtainTokenMessage(request, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_002, TestSize.Level0)
{
    CreateDefaultRequest();
    Attributes request;
    OnMessageReply onMessageReply = nullptr;
    request_->HandleObtainTokenMessage(request, onMessageReply);
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_003, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, receivedResult));
    };

    Attributes request;
    request_->HandleObtainTokenMessage(request, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::INVALID_PARAMETERS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_004, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    Attributes request;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 101,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = companionDeviceKey_ };
    EncodeObtainTokenRequest(obtainTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, receivedResult));
    };

    request_->HandleObtainTokenMessage(request, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::INVALID_PARAMETERS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_005, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    Attributes request;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 100,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = companionDeviceKey_ };
    obtainTokenRequest.companionDeviceKey.deviceId = "mismatch_device_id";
    EncodeObtainTokenRequest(obtainTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, receivedResult));
    };

    request_->HandleObtainTokenMessage(request, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::INVALID_PARAMETERS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_006, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));
    request_->peerDeviceKey_ = DeviceKey {};

    Attributes request;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 100,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = companionDeviceKey_ };
    EncodeObtainTokenRequest(obtainTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, receivedResult));
    };

    request_->HandleObtainTokenMessage(request, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::INVALID_PARAMETERS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_007, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    Attributes request;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 100,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = companionDeviceKey_ };
    EncodeObtainTokenRequest(obtainTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    bool replyCalled = false;
    int32_t receivedResult = -1;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, receivedResult));
    };

    EXPECT_CALL(mockSecurityAgent_, HostProcessObtainToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleObtainTokenMessage(request, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, ParsePreObtainTokenRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    DeviceKey deviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "different_device_id",
        .deviceUserId = 300 };
    request_->peerDeviceKey_ = deviceKey;

    bool result = request_->ParsePreObtainTokenRequest(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, ParsePreObtainTokenRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::nullopt));

    bool result = request_->ParsePreObtainTokenRequest(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, HandleHostProcessObtainToken_001, TestSize.Level0)
{
    CreateDefaultRequest();

    ObtainTokenRequest request = { .hostUserId = 100, .extraInfo = {}, .companionDeviceKey = companionDeviceKey_ };
    std::vector<uint8_t> obtainTokenReply;

    bool result = request_->HandleHostProcessObtainToken(request, obtainTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, HandleHostProcessObtainToken_002, TestSize.Level0)
{
    CreateDefaultRequest();

    ObtainTokenRequest request = { .hostUserId = 100, .extraInfo = {}, .companionDeviceKey = companionDeviceKey_ };
    std::vector<uint8_t> obtainTokenReply;

    EXPECT_CALL(mockCompanionManager_, SetCompanionTokenAtl(_, _)).WillOnce(Return(true));

    bool result = request_->HandleHostProcessObtainToken(request, obtainTokenReply);

    EXPECT_TRUE(result);
}

HWTEST_F(HostObtainTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockSecurityAgent_, HostCancelObtainToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->needCancelObtainToken_ = true;
    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostObtainTokenRequestTest, CompleteWithError_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockSecurityAgent_, HostCancelObtainToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->needCancelObtainToken_ = true;
    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostObtainTokenRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostObtainTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    CreateDefaultRequest();

    uint32_t concurrency = request_->GetMaxConcurrency();
    EXPECT_EQ(concurrency, 10);
}

HWTEST_F(HostObtainTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostObtainTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->peerDeviceKey_ = std::nullopt;

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_OBTAIN_TOKEN_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostObtainTokenRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_OBTAIN_TOKEN_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, EnsureCompanionAuthMaintainActive_001, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_))
        .WillOnce(Return(
            std::make_optional(DeviceStatus { .deviceKey = companionDeviceKey_, .isAuthMaintainActive = false })));

    bool result = request_->EnsureCompanionAuthMaintainActive(companionDeviceKey_, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, EnsureCompanionAuthMaintainActive_002, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(nullptr));

    bool result = request_->EnsureCompanionAuthMaintainActive(companionDeviceKey_, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, HandlePeerDeviceStatusChanged_001, TestSize.Level0)
{
    CreateDefaultRequest();

    DeviceKey deviceKey;
    DeviceStatus status;
    status.deviceKey = deviceKey;
    std::vector<DeviceStatus> deviceStatusList = { status };

    request_->HandlePeerDeviceStatusChanged(deviceStatusList);
}

HWTEST_F(HostObtainTokenRequestTest, HandlePeerDeviceStatusChanged_002, TestSize.Level0)
{
    CreateDefaultRequest();

    DeviceKey deviceKey = request_->peerDeviceKey_.value();
    DeviceStatus status;
    status.deviceKey = deviceKey;
    status.isAuthMaintainActive = true;
    std::vector<DeviceStatus> deviceStatusList = { status };

    request_->HandlePeerDeviceStatusChanged(deviceStatusList);
}

HWTEST_F(HostObtainTokenRequestTest, HandlePeerDeviceStatusChanged_003, TestSize.Level0)
{
    CreateDefaultRequest();

    DeviceKey deviceKey = request_->peerDeviceKey_.value();
    DeviceStatus status;
    status.deviceKey = deviceKey;
    status.isAuthMaintainActive = false;
    std::vector<DeviceStatus> deviceStatusList = { status };

    request_->HandlePeerDeviceStatusChanged(deviceStatusList);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
