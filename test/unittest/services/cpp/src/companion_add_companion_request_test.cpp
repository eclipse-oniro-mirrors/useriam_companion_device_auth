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

#include "add_companion_message.h"
#include "companion_add_companion_request.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "relative_timer.h"
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

class CompanionAddCompanionRequestTest : public Test {
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

        InitKeyNegotiationRequest initRequest;
        initRequest.hostDeviceKey = hostDeviceKey_;
        initRequest.extraInfo = { 1, 2, 3, 4 };
        initKeyNegoRequest_.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, initRequest.hostDeviceKey.deviceUserId);
        initKeyNegoRequest_.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
            static_cast<int32_t>(initRequest.hostDeviceKey.idType));
        initKeyNegoRequest_.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, initRequest.hostDeviceKey.deviceId);
        initKeyNegoRequest_.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, initRequest.extraInfo);

        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
        ON_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
            .WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockSecurityAgent_, CompanionInitKeyNegotiation(_, _))
            .WillByDefault(
                Invoke([](const CompanionInitKeyNegotiationInput &, CompanionInitKeyNegotiationOutput &output) {
                    output.initKeyNegotiationReply = { 5, 6, 7, 8 };
                    return ResultCode::SUCCESS;
                }));
        ON_CALL(mockHostBindingManager_, BeginAddHostBinding(_, _, _, _, _))
            .WillByDefault(Invoke(
                [](int32_t, int32_t, SecureProtocolId, const std::vector<uint8_t> &, std::vector<uint8_t> &output) {
                    output = { 9, 10, 11, 12 };
                    return ResultCode::SUCCESS;
                }));
        ON_CALL(mockHostBindingManager_, EndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
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
        request_ = std::make_shared<CompanionAddCompanionRequest>(connectionName_, initKeyNegoRequest_, onMessageReply_,
            hostDeviceKey_);
    }

protected:
    std::shared_ptr<CompanionAddCompanionRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;

    std::string connectionName_ = "test_connection";
    Attributes initKeyNegoRequest_;
    OnMessageReply onMessageReply_ = [](const Attributes &) {};
    DeviceKey hostDeviceKey_ = { .deviceId = "host_device_id", .deviceUserId = 100 };
    DeviceKey companionDeviceKey_ = { .deviceId = "companion_device_id", .deviceUserId = 200 };
};

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_001, TestSize.Level0)
{
    bool replyCalled = false;
    ResultCode receivedResult = ResultCode::GENERAL_ERROR;
    onMessageReply_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto replyOpt = DecodeInitKeyNegotiationReply(reply);
        if (replyOpt.has_value()) {
            receivedResult = replyOpt->result;
        }
    };

    request_ = std::make_shared<CompanionAddCompanionRequest>(connectionName_, initKeyNegoRequest_, onMessageReply_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockSecurityAgent_, CompanionInitKeyNegotiation(_, _))
        .WillOnce(Invoke([](const CompanionInitKeyNegotiationInput &, CompanionInitKeyNegotiationOutput &output) {
            output.initKeyNegotiationReply = { 5, 6, 7, 8 };
            return ResultCode::SUCCESS;
        }));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, ResultCode::SUCCESS);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_002, TestSize.Level0)
{
    bool replyCalled = false;
    onMessageReply_ = [&replyCalled](const Attributes &) { replyCalled = true; };

    request_ = std::make_shared<CompanionAddCompanionRequest>(connectionName_, initKeyNegoRequest_, onMessageReply_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_FALSE(replyCalled);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_003, TestSize.Level0)
{
    bool replyCalled = false;
    onMessageReply_ = [&replyCalled](const Attributes &) { replyCalled = true; };

    request_ = std::make_shared<CompanionAddCompanionRequest>(connectionName_, initKeyNegoRequest_, onMessageReply_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_004, TestSize.Level0)
{
    bool replyCalled = false;
    onMessageReply_ = [&replyCalled](const Attributes &) { replyCalled = true; };

    request_ = std::make_shared<CompanionAddCompanionRequest>(connectionName_, initKeyNegoRequest_, onMessageReply_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_005, TestSize.Level0)
{
    bool replyCalled = false;
    onMessageReply_ = [&replyCalled](const Attributes &) { replyCalled = true; };

    Attributes emptyRequest;
    request_ =
        std::make_shared<CompanionAddCompanionRequest>(connectionName_, emptyRequest, onMessageReply_, hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_006, TestSize.Level0)
{
    bool replyCalled = false;
    onMessageReply_ = [&replyCalled](const Attributes &) { replyCalled = true; };

    request_ = std::make_shared<CompanionAddCompanionRequest>(connectionName_, initKeyNegoRequest_, onMessageReply_,
        hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockSecurityAgent_, CompanionInitKeyNegotiation(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_001, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    request_->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserId = companionDeviceKey_.deviceUserId;
    beginRequest.extraInfo = { 13, 14, 15, 16 };
    Attributes attrInput;
    EncodeBeginAddHostBindingRequest(beginRequest, attrInput);

    bool replyCalled = false;
    ResultCode receivedResult = ResultCode::GENERAL_ERROR;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto replyOpt = DecodeBeginAddHostBindingReply(reply);
        if (replyOpt.has_value()) {
            receivedResult = replyOpt->result;
        }
    };

    EXPECT_CALL(mockHostBindingManager_, BeginAddHostBinding(_, _, _, _, _))
        .WillOnce(
            Invoke([](int32_t, int32_t, SecureProtocolId, const std::vector<uint8_t> &, std::vector<uint8_t> &output) {
                output = { 9, 10, 11, 12 };
                return ResultCode::SUCCESS;
            }));

    request_->HandleBeginAddCompanion(attrInput, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, ResultCode::SUCCESS);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_002, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    request_->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserId = companionDeviceKey_.deviceUserId;
    beginRequest.extraInfo = { 13, 14, 15, 16 };
    Attributes attrInput;
    EncodeBeginAddHostBindingRequest(beginRequest, attrInput);

    OnMessageReply onMessageReply = nullptr;

    request_->HandleBeginAddCompanion(attrInput, onMessageReply);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_003, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    request_->OnStart(errorGuard);

    Attributes attrInput;

    bool replyCalled = false;
    ResultCode receivedResult = ResultCode::SUCCESS;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        receivedResult = static_cast<ResultCode>(result);
    };

    request_->HandleBeginAddCompanion(attrInput, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_004, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    request_->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserId = companionDeviceKey_.deviceUserId;
    beginRequest.extraInfo = { 13, 14, 15, 16 };
    Attributes attrInput;
    EncodeBeginAddHostBindingRequest(beginRequest, attrInput);

    bool replyCalled = false;
    ResultCode receivedResult = ResultCode::SUCCESS;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        receivedResult = static_cast<ResultCode>(result);
    };

    EXPECT_CALL(mockHostBindingManager_, BeginAddHostBinding(_, _, _, _, _)).WillOnce(Return(ResultCode::FAIL));

    request_->HandleBeginAddCompanion(attrInput, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, ResultCode::FAIL);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_001, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    request_->OnStart(errorGuard);

    EndAddHostBindingRequest endRequest;
    endRequest.hostDeviceKey = hostDeviceKey_;
    endRequest.companionUserId = companionDeviceKey_.deviceUserId;
    endRequest.result = ResultCode::SUCCESS;
    Attributes attrInput;
    EncodeEndAddHostBindingRequest(endRequest, attrInput);
    attrInput.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(endRequest.hostDeviceKey.idType));
    attrInput.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, endRequest.hostDeviceKey.deviceId);

    bool replyCalled = false;
    ResultCode receivedResult = ResultCode::GENERAL_ERROR;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        auto replyOpt = DecodeEndAddHostBindingReply(reply);
        if (replyOpt.has_value()) {
            receivedResult = replyOpt->result;
        }
    };

    EXPECT_CALL(mockHostBindingManager_, EndAddHostBinding(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->HandleEndAddCompanion(attrInput, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, ResultCode::SUCCESS);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_002, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    request_->OnStart(errorGuard);

    EndAddHostBindingRequest endRequest;
    endRequest.hostDeviceKey = hostDeviceKey_;
    endRequest.companionUserId = companionDeviceKey_.deviceUserId;
    endRequest.result = ResultCode::SUCCESS;
    Attributes attrInput;
    EncodeEndAddHostBindingRequest(endRequest, attrInput);
    attrInput.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(endRequest.hostDeviceKey.idType));
    attrInput.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, endRequest.hostDeviceKey.deviceId);

    OnMessageReply onMessageReply = nullptr;

    request_->HandleEndAddCompanion(attrInput, onMessageReply);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_003, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    request_->OnStart(errorGuard);

    Attributes attrInput;

    bool replyCalled = false;
    ResultCode receivedResult = ResultCode::SUCCESS;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        receivedResult = static_cast<ResultCode>(result);
    };

    request_->HandleEndAddCompanion(attrInput, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_004, TestSize.Level0)
{
    CreateDefaultRequest();
    ErrorGuard errorGuard([](ResultCode) {});
    request_->OnStart(errorGuard);

    EndAddHostBindingRequest endRequest;
    endRequest.hostDeviceKey = hostDeviceKey_;
    endRequest.companionUserId = companionDeviceKey_.deviceUserId;
    endRequest.result = ResultCode::SUCCESS;
    Attributes attrInput;
    EncodeEndAddHostBindingRequest(endRequest, attrInput);
    attrInput.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(endRequest.hostDeviceKey.idType));
    attrInput.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, endRequest.hostDeviceKey.deviceId);

    bool replyCalled = false;
    ResultCode receivedResult = ResultCode::SUCCESS;
    OnMessageReply onMessageReply = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        receivedResult = static_cast<ResultCode>(result);
    };

    EXPECT_CALL(mockHostBindingManager_, EndAddHostBinding(_, _))
        .WillOnce(Return(ResultCode::FAIL))
        .WillOnce(Return(ResultCode::FAIL));

    request_->HandleEndAddCompanion(attrInput, onMessageReply);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, ResultCode::FAIL);
}

HWTEST_F(CompanionAddCompanionRequestTest, CompleteWithError_001, TestSize.Level0)
{
    bool replyCalled = false;
    ResultCode receivedResult = ResultCode::SUCCESS;
    onMessageReply_ = [&replyCalled, &receivedResult](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        receivedResult = static_cast<ResultCode>(result);
    };

    request_ = std::make_shared<CompanionAddCompanionRequest>(connectionName_, initKeyNegoRequest_, onMessageReply_,
        hostDeviceKey_);

    request_->CompleteWithError(ResultCode::COMMUNICATION_ERROR);

    EXPECT_TRUE(replyCalled);
    EXPECT_EQ(receivedResult, ResultCode::COMMUNICATION_ERROR);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
