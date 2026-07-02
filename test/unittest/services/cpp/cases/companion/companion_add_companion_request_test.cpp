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

#include "add_companion_message.h"
#include "companion_add_companion_request.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

const std::string CONNECTION_NAME = "test_connection";
const DeviceKey HOST_DEVICE_KEY = { .deviceId = "host_device_id", .deviceUserId = 100 };
const DeviceKey COMPANION_DEVICE_KEY = { .deviceId = "companion_device_id", .deviceUserId = 200 };

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class CompanionAddCompanionRequestTest : public Test {
protected:
};

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    OnMessageReply onMessageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto replyOpt = DecodeInitKeyNegotiationReply(reply);
        if (replyOpt.has_value()) {
            *receivedResult = replyOpt->result;
        }
    };

    Attributes initKeyNegoRequest;
    InitKeyNegotiationRequest initRequest;
    initRequest.hostDeviceKey = HOST_DEVICE_KEY;
    initRequest.extraInfo = { 1, 2, 1, 4 };
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, initRequest.hostDeviceKey.deviceUserId);
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(initRequest.hostDeviceKey.idType));
    initKeyNegoRequest.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, initRequest.hostDeviceKey.deviceId);
    initKeyNegoRequest.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, initRequest.extraInfo);

    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(Invoke([](const CompanionInitKeyNegotiationInput &, CompanionInitKeyNegotiationOutput &output) {
            output.initKeyNegotiationReply = { 5, 6, 7, 8 };
            return ResultCode::SUCCESS;
        }));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::SUCCESS);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &) { *replyCalled = true; };

    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_FALSE(*replyCalled);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &) { *replyCalled = true; };

    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &) { *replyCalled = true; };

    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_005, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &) { *replyCalled = true; };

    Attributes emptyRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, emptyRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_006, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &) { *replyCalled = true; };

    Attributes initKeyNegoRequest;
    InitKeyNegotiationRequest initRequest;
    initRequest.hostDeviceKey = HOST_DEVICE_KEY;
    initRequest.extraInfo = { 1, 2, 1, 4 };
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, initRequest.hostDeviceKey.deviceUserId);
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(initRequest.hostDeviceKey.idType));
    initKeyNegoRequest.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, initRequest.hostDeviceKey.deviceId);
    initKeyNegoRequest.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, initRequest.extraInfo);

    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_007, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &) { *replyCalled = true; };

    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);
    request->peerDeviceKey_ = COMPANION_DEVICE_KEY;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_FALSE(*replyCalled);
}

HWTEST_F(CompanionAddCompanionRequestTest, OnStart_008, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &) { *replyCalled = true; };

    Attributes initKeyNegoRequest;
    InitKeyNegotiationRequest initRequest;
    initRequest.hostDeviceKey = HOST_DEVICE_KEY;
    initRequest.extraInfo = { 1, 2, 1, 4 };
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, initRequest.hostDeviceKey.deviceUserId);
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(initRequest.hostDeviceKey.idType));
    initKeyNegoRequest.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, initRequest.hostDeviceKey.deviceId);
    initKeyNegoRequest.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, initRequest.extraInfo);

    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);
    request->currentReply_ = nullptr;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(Invoke([](const CompanionInitKeyNegotiationInput &, CompanionInitKeyNegotiationOutput &output) {
            output.initKeyNegotiationReply = { 5, 6, 7, 8 };
            return ResultCode::SUCCESS;
        }));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(result);
    EXPECT_FALSE(*replyCalled);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(COMPANION_DEVICE_KEY));

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserId = COMPANION_DEVICE_KEY.deviceUserId;
    beginRequest.extraInfo = { 13, 14, 15, 16 };
    Attributes attrInput;
    EncodeBeginAddHostBindingRequest(beginRequest, attrInput);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    OnMessageReply messageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto replyOpt = DecodeBeginAddHostBindingReply(reply);
        if (replyOpt.has_value()) {
            *receivedResult = replyOpt->result;
        }
    };

    EXPECT_CALL(guard.GetHostBindingManager(), BeginAddHostBinding(_, _))
        .WillOnce(Invoke([](const BeginAddHostBindingInput &, BeginAddHostBindingOutput &output) {
            output.addHostBindingReply = { 9, 10, 11, 12 };
            output.bindingId = 1;
            return ResultCode::SUCCESS;
        }));

    request->HandleBeginAddCompanion(attrInput, messageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::SUCCESS);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_002, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserId = COMPANION_DEVICE_KEY.deviceUserId;
    beginRequest.extraInfo = { 13, 14, 15, 16 };
    Attributes attrInput;
    EncodeBeginAddHostBindingRequest(beginRequest, attrInput);

    OnMessageReply messageReply = nullptr;

    ASSERT_NO_THROW(request->HandleBeginAddCompanion(attrInput, messageReply));
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_003, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    Attributes attrInput;

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    OnMessageReply messageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        *receivedResult = static_cast<ResultCode>(result);
    };

    request->HandleBeginAddCompanion(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(COMPANION_DEVICE_KEY));

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserId = COMPANION_DEVICE_KEY.deviceUserId;
    beginRequest.extraInfo = { 13, 14, 15, 16 };
    Attributes attrInput;
    EncodeBeginAddHostBindingRequest(beginRequest, attrInput);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    OnMessageReply messageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        *receivedResult = static_cast<ResultCode>(result);
    };

    EXPECT_CALL(guard.GetHostBindingManager(), BeginAddHostBinding(_, _)).WillOnce(Return(ResultCode::FAIL));

    request->HandleBeginAddCompanion(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::FAIL);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_001, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    EndAddHostBindingRequest endRequest;
    endRequest.hostDeviceKey = HOST_DEVICE_KEY;
    endRequest.companionUserId = COMPANION_DEVICE_KEY.deviceUserId;
    endRequest.result = ResultCode::SUCCESS;
    Attributes attrInput;
    EncodeEndAddHostBindingRequest(endRequest, attrInput);
    attrInput.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(endRequest.hostDeviceKey.idType));
    attrInput.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, endRequest.hostDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    OnMessageReply messageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        auto replyOpt = DecodeEndAddHostBindingReply(reply);
        if (replyOpt.has_value()) {
            *receivedResult = replyOpt->result;
        }
    };

    EXPECT_CALL(guard.GetHostBindingManager(), EndAddHostBinding(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request->HandleEndAddCompanion(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::SUCCESS);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_002, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    EndAddHostBindingRequest endRequest;
    endRequest.hostDeviceKey = HOST_DEVICE_KEY;
    endRequest.companionUserId = COMPANION_DEVICE_KEY.deviceUserId;
    endRequest.result = ResultCode::SUCCESS;
    Attributes attrInput;
    EncodeEndAddHostBindingRequest(endRequest, attrInput);
    attrInput.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(endRequest.hostDeviceKey.idType));
    attrInput.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, endRequest.hostDeviceKey.deviceId);

    OnMessageReply messageReply = nullptr;

    ASSERT_NO_THROW(request->HandleEndAddCompanion(attrInput, messageReply));
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_003, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    Attributes attrInput;

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    OnMessageReply messageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        *receivedResult = static_cast<ResultCode>(result);
    };

    request->HandleEndAddCompanion(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_004, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    EndAddHostBindingRequest endRequest;
    endRequest.hostDeviceKey = HOST_DEVICE_KEY;
    endRequest.companionUserId = COMPANION_DEVICE_KEY.deviceUserId;
    endRequest.result = ResultCode::SUCCESS;
    Attributes attrInput;
    EncodeEndAddHostBindingRequest(endRequest, attrInput);
    attrInput.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(endRequest.hostDeviceKey.idType));
    attrInput.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, endRequest.hostDeviceKey.deviceId);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    OnMessageReply messageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        *receivedResult = static_cast<ResultCode>(result);
    };

    EXPECT_CALL(guard.GetHostBindingManager(), EndAddHostBinding(_, _)).WillOnce(Return(ResultCode::FAIL));

    request->HandleEndAddCompanion(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::FAIL);
}

HWTEST_F(CompanionAddCompanionRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    OnMessageReply onMessageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        *receivedResult = static_cast<ResultCode>(result);
    };

    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    request->CompleteWithError(ResultCode::COMMUNICATION_ERROR);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(CompanionAddCompanionRequestTest, SendErrorReply_001, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);
    request->currentReply_ = nullptr;

    ASSERT_NO_THROW(request->SendErrorReply(ResultCode::SUCCESS));
}

HWTEST_F(CompanionAddCompanionRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    EXPECT_EQ(request->GetMaxConcurrency(), 1);
}

HWTEST_F(CompanionAddCompanionRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddCompanion_005, TestSize.Level0)
{
    MockGuard guard;

    DeviceKey wrongDeviceKey = { .deviceId = "wrong_device_id", .deviceUserId = 999 };
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(wrongDeviceKey));

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserId = COMPANION_DEVICE_KEY.deviceUserId;
    beginRequest.extraInfo = { 13, 14, 15, 16 };
    Attributes attrInput;
    EncodeBeginAddHostBindingRequest(beginRequest, attrInput);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    OnMessageReply messageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        *receivedResult = static_cast<ResultCode>(result);
    };

    request->HandleBeginAddCompanion(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddCompanion_005, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    EndAddHostBindingRequest endRequest;
    endRequest.hostDeviceKey = { .deviceId = "wrong_host_id", .deviceUserId = 999 };
    endRequest.companionUserId = COMPANION_DEVICE_KEY.deviceUserId;
    endRequest.result = ResultCode::SUCCESS;
    Attributes attrInput;
    EncodeEndAddHostBindingRequest(endRequest, attrInput);

    auto replyCalled = std::make_shared<bool>(false);
    auto receivedResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    OnMessageReply messageReply = [replyCalled, receivedResult](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        *receivedResult = static_cast<ResultCode>(result);
    };

    request->HandleEndAddCompanion(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
