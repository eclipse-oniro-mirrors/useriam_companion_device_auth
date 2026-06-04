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

#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_event_manager_adapter.h"
#include "mock_misc_manager.h"
#include "mock_request.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_time_keeper.h"
#include "mock_user_id_manager.h"

#include "adapter_manager.h"
#include "host_obtain_token_request.h"
#include "obtain_token_message.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// 测试数据常量
const TemplateId TEST_TEMPLATE_ID = 1;
const std::string CONNECTION_NAME = "test_connection";
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };
const DeviceStatus DEVICE_STATUS = { .deviceKey = COMPANION_DEVICE_KEY, .isAuthMaintainActive = true };

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

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto userIdMgr = std::shared_ptr<IUserIdManager>(&mockUserIdManager_, [](IUserIdManager *) {});
        AdapterManager::GetInstance().SetUserIdManager(userIdMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        auto eventManagerAdapter =
            std::shared_ptr<IEventManagerAdapter>(&mockEventManagerAdapter_, [](IEventManagerAdapter *) {});
        AdapterManager::GetInstance().SetEventManagerAdapter(eventManagerAdapter);

        CompanionStatus companionStatus;
        companionStatus.templateId = TEST_TEMPLATE_ID;
        ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
            .WillByDefault(Return(std::make_optional(companionStatus)));
        ON_CALL(mockCompanionManager_, IsCapabilitySupported(_, Capability::OBTAIN_TOKEN)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
            .WillByDefault(Return(std::make_optional(SecureProtocolId::DEFAULT)));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_))
            .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockSecurityAgent_, HostProcessPreObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostProcessObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockEventManagerAdapter_, ReportInteractionEvent(_)).WillByDefault(Return());
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

    Attributes MakePreObtainTokenRequest()
    {
        PreObtainTokenRequest preRequest = { .hostUserId = 100,
            .companionDeviceKey = COMPANION_DEVICE_KEY,
            .extraInfo = { 1, 2, 3 } };
        Attributes preObtainTokenRequest;
        EncodePreObtainTokenRequest(preRequest, preObtainTokenRequest);
        preObtainTokenRequest.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
            static_cast<int32_t>(preRequest.companionDeviceKey.idType));
        preObtainTokenRequest.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER,
            preRequest.companionDeviceKey.deviceId);
        return preObtainTokenRequest;
    }

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserIdManager> mockUserIdManager_;
    NiceMock<MockEventManagerAdapter> mockEventManagerAdapter_;
};

HWTEST_F(HostObtainTokenRequestTest, OnStart_001, TestSize.Level0)
{
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto decodedReply = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(decodedReply.has_value());
        *receivedResult = decodedReply.value().result;
    };

    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    CompanionStatus companionStatus;
    companionStatus.templateId = TEST_TEMPLATE_ID;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(mockSecurityAgent_, HostProcessPreObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _)).WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_002, TestSize.Level0)
{
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto decodedReply = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(decodedReply.has_value());
        *receivedResult = decodedReply.value().result;
    };

    Attributes emptyRequest;
    DeviceKey emptyKey {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, emptyRequest,
        OnMessageReply(onMessageReply), emptyKey);

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_003, TestSize.Level0)
{
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto decodedReply = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(decodedReply.has_value());
        *receivedResult = decodedReply.value().result;
    };

    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_004, TestSize.Level0)
{
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto decodedReply = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(decodedReply.has_value());
        *receivedResult = decodedReply.value().result;
    };

    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    CompanionStatus companionStatus;
    companionStatus.templateId = TEST_TEMPLATE_ID;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_005, TestSize.Level0)
{
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto decodedReply = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(decodedReply.has_value());
        *receivedResult = decodedReply.value().result;
    };

    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    CompanionStatus companionStatus;
    companionStatus.templateId = TEST_TEMPLATE_ID;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(mockSecurityAgent_, HostProcessPreObtainToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, OnStart_006, TestSize.Level0)
{
    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto decodedReply = DecodePreObtainTokenReply(reply);
        EXPECT_TRUE(decodedReply.has_value());
        *receivedResult = decodedReply.value().result;
    };

    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    CompanionStatus companionStatus;
    companionStatus.templateId = TEST_TEMPLATE_ID;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(mockSecurityAgent_, HostProcessPreObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    Attributes req;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 100,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = COMPANION_DEVICE_KEY };
    EncodeObtainTokenRequest(obtainTokenRequest, req);
    req.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    req.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply messageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, *receivedResult));
    };

    EXPECT_CALL(mockSecurityAgent_, HostProcessObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCompanionManager_, SetCompanionTokenAuthAtl(_, _, _)).WillOnce(Return(true));

    request->HandleObtainTokenMessage(req, messageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_002, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    Attributes req;
    OnMessageReply messageReply = nullptr;
    ASSERT_NO_THROW(request->HandleObtainTokenMessage(req, messageReply));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_003, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply messageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, *receivedResult));
    };

    Attributes req;
    request->HandleObtainTokenMessage(req, messageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::INVALID_PARAMETERS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_004, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    Attributes req;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 101,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = COMPANION_DEVICE_KEY };
    EncodeObtainTokenRequest(obtainTokenRequest, req);
    req.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    req.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply messageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, *receivedResult));
    };

    request->HandleObtainTokenMessage(req, messageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::INVALID_PARAMETERS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_005, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    Attributes req;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 100,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = COMPANION_DEVICE_KEY };
    obtainTokenRequest.companionDeviceKey.deviceId = "mismatch_device_id";
    EncodeObtainTokenRequest(obtainTokenRequest, req);
    req.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    req.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply messageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, *receivedResult));
    };

    request->HandleObtainTokenMessage(req, messageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::INVALID_PARAMETERS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_006, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));
    request->peerDeviceKey_ = DeviceKey {};

    Attributes req;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 100,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = COMPANION_DEVICE_KEY };
    EncodeObtainTokenRequest(obtainTokenRequest, req);
    req.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    req.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply messageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, *receivedResult));
    };

    request->HandleObtainTokenMessage(req, messageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::INVALID_PARAMETERS));
}

HWTEST_F(HostObtainTokenRequestTest, HandleObtainTokenMessage_007, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    Attributes req;
    ObtainTokenRequest obtainTokenRequest = { .hostUserId = 100,
        .extraInfo = { 1, 2, 3 },
        .companionDeviceKey = COMPANION_DEVICE_KEY };
    EncodeObtainTokenRequest(obtainTokenRequest, req);
    req.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(obtainTokenRequest.companionDeviceKey.idType));
    req.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, obtainTokenRequest.companionDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<int32_t>(-1);
    OnMessageReply messageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        *replyCalled = true;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, *receivedResult));
    };

    EXPECT_CALL(mockSecurityAgent_, HostProcessObtainToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandleObtainTokenMessage(req, messageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, ParsePreObtainTokenRequest_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    DeviceKey deviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "different_device_id",
        .deviceUserId = 300 };
    request->peerDeviceKey_ = deviceKey;

    bool result = request->ParsePreObtainTokenRequest(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, ParsePreObtainTokenRequest_002, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::nullopt));

    bool result = request->ParsePreObtainTokenRequest(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, HandleHostProcessObtainToken_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ObtainTokenRequest req = { .hostUserId = 100, .extraInfo = {}, .companionDeviceKey = COMPANION_DEVICE_KEY };
    std::vector<uint8_t> obtainTokenReply;

    bool result = request->HandleHostProcessObtainToken(req, obtainTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, HandleHostProcessObtainToken_002, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ObtainTokenRequest req = { .hostUserId = 100, .extraInfo = {}, .companionDeviceKey = COMPANION_DEVICE_KEY };
    std::vector<uint8_t> obtainTokenReply;

    request->templateId_ = TEST_TEMPLATE_ID;
    EXPECT_CALL(mockCompanionManager_, SetCompanionTokenAuthAtl(_, _, _)).WillOnce(Return(true));

    bool result = request->HandleHostProcessObtainToken(req, obtainTokenReply);

    EXPECT_TRUE(result);
}

HWTEST_F(HostObtainTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    EXPECT_CALL(mockSecurityAgent_, HostCancelObtainToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request->needCancelObtainToken_ = true;
    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, CompleteWithError_002, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    EXPECT_CALL(mockSecurityAgent_, HostCancelObtainToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->needCancelObtainToken_ = true;
    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostObtainTokenRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostObtainTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    uint32_t concurrency = request->GetMaxConcurrency();
    EXPECT_EQ(concurrency, 10);
}

HWTEST_F(HostObtainTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostObtainTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    DeviceKey emptyKey {};
    request->peerDeviceKey_ = emptyKey;

    // When peerDeviceKey_ is an empty DeviceKey and new request has nullopt, they don't match
    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_OBTAIN_TOKEN_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_OBTAIN_TOKEN_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, EnsureCompanionAuthMaintainActive_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_))
        .WillOnce(Return(
            std::make_optional(DeviceStatus { .deviceKey = COMPANION_DEVICE_KEY, .isAuthMaintainActive = false })));

    bool result = request->EnsureCompanionAuthMaintainActive(COMPANION_DEVICE_KEY, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, EnsureCompanionAuthMaintainActive_002, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _)).WillOnce(Return(nullptr));

    bool result = request->EnsureCompanionAuthMaintainActive(COMPANION_DEVICE_KEY, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostObtainTokenRequestTest, HandlePeerDeviceStatusChanged_001, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    DeviceKey deviceKey;
    DeviceStatus status;
    status.deviceKey = deviceKey;
    std::vector<DeviceStatus> deviceStatusList = { status };

    ASSERT_NO_THROW(request->HandlePeerDeviceStatusChanged(deviceStatusList));
}

HWTEST_F(HostObtainTokenRequestTest, HandlePeerDeviceStatusChanged_002, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    DeviceKey deviceKey = request->peerDeviceKey_;
    DeviceStatus status;
    status.deviceKey = deviceKey;
    status.isAuthMaintainActive = true;
    std::vector<DeviceStatus> deviceStatusList = { status };

    ASSERT_NO_THROW(request->HandlePeerDeviceStatusChanged(deviceStatusList));
}

HWTEST_F(HostObtainTokenRequestTest, HandlePeerDeviceStatusChanged_003, TestSize.Level0)
{
    auto preObtainTokenRequest = MakePreObtainTokenRequest();
    auto onMessageReply = [](const Attributes &) {};
    auto request = std::make_shared<HostObtainTokenRequest>(CONNECTION_NAME, preObtainTokenRequest,
        OnMessageReply(onMessageReply), COMPANION_DEVICE_KEY);

    DeviceKey deviceKey = request->peerDeviceKey_;
    DeviceStatus status;
    status.deviceKey = deviceKey;
    status.isAuthMaintainActive = false;
    std::vector<DeviceStatus> deviceStatusList = { status };

    ASSERT_NO_THROW(request->HandlePeerDeviceStatusChanged(deviceStatusList));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
