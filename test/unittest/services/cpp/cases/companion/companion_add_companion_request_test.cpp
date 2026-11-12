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
constexpr ProtocolId UNSUPPORTED_PROTOCOL_ID = static_cast<ProtocolId>(99);

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

LocalDeviceProfile MakeCompanionProfile()
{
    LocalDeviceProfile profile = {};
    profile.protocols = { ProtocolId::VERSION_1 };
    profile.companionCapabilities = { Capability::TOKEN_AUTH };
    return profile;
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
    initRequest.protocolId = ProtocolId::VERSION_1;
    initRequest.extraInfo = { 1, 2, 1, 4 };
    EncodeInitKeyNegotiationRequest(initRequest, initKeyNegoRequest);
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(initRequest.hostDeviceKey.idType));
    initKeyNegoRequest.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, initRequest.hostDeviceKey.deviceId);

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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(MakeCompanionProfile()));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(Invoke([](const CompanionInitKeyNegotiationInput &input, CompanionInitKeyNegotiationOutput &output) {
            EXPECT_EQ(input.companionProtocolList,
                std::vector<uint16_t> { static_cast<uint16_t>(ProtocolId::VERSION_1) });
            EXPECT_EQ(input.companionCapabilityList,
                std::vector<uint16_t> { static_cast<uint16_t>(Capability::TOKEN_AUTH) });
            EXPECT_EQ(input.companionDeviceKey.deviceId, COMPANION_DEVICE_KEY.deviceId);
            EXPECT_EQ(input.hostDeviceKey.deviceId, HOST_DEVICE_KEY.deviceId);
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

// A rejected offer reaches the host with the negotiation code itself, so the host can tell a
// binding that can never succeed apart from a transient local failure.
HWTEST_F(CompanionAddCompanionRequestTest, OnStart_NegotiationFailureReportsResultCode, TestSize.Level0)
{
    MockGuard guard;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &) { *replyCalled = true; };

    InitKeyNegotiationRequest initRequest;
    initRequest.hostDeviceKey = HOST_DEVICE_KEY;
    initRequest.protocolId = UNSUPPORTED_PROTOCOL_ID;
    initRequest.extraInfo = { 1, 2, 1, 4 };
    Attributes initKeyNegoRequest;
    EncodeInitKeyNegotiationRequest(initRequest, initKeyNegoRequest);
    // Emulate the receiving-side MessageRouter stamping the sender identity into the payload
    // (message_router.cpp); message encoders omit these transport attributes by design.
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(initRequest.hostDeviceKey.idType));
    initKeyNegoRequest.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, initRequest.hostDeviceKey.deviceId);

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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(MakeCompanionProfile()));

    auto reportedCode = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    {
        ErrorGuard errorGuard([reportedCode](ResultCode result) { *reportedCode = result; });
        EXPECT_FALSE(request->OnStart(errorGuard));
    }

    EXPECT_EQ(*reportedCode, ResultCode::PROTOCOL_NEGOTIATION_FAILED);
    EXPECT_FALSE(*replyCalled);
}

// An algorithm-negotiation failure (20015) inside the secure layer must reach the host verbatim
// in the INIT_KEY_NEGOTIATION error reply (via CompleteWithError -> SendErrorReply); flattening
// it into GENERAL_ERROR would hide the renegotiation trigger from the host.
HWTEST_F(CompanionAddCompanionRequestTest, OnStart_InitKeyNegoFailureReportsAlgorithmNegotiationFailed, TestSize.Level0)
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

    InitKeyNegotiationRequest initRequest;
    initRequest.hostDeviceKey = HOST_DEVICE_KEY;
    initRequest.protocolId = ProtocolId::VERSION_1;
    initRequest.extraInfo = { 1, 2, 1, 4 };
    Attributes initKeyNegoRequest;
    EncodeInitKeyNegotiationRequest(initRequest, initKeyNegoRequest);
    initKeyNegoRequest.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(initRequest.hostDeviceKey.idType));
    initKeyNegoRequest.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, initRequest.hostDeviceKey.deviceId);

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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(MakeCompanionProfile()));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionInitKeyNegotiation(_, _))
        .WillOnce(Return(ResultCode::ALGORITHM_NEGOTIATION_FAILED));

    // Mirror the production wiring in inbound_request.cpp: the guard's completion callback is
    // the request's CompleteWithError, which sends the error reply on the wire.
    {
        ErrorGuard errorGuard([request](ResultCode result) { request->CompleteWithError(result); });
        EXPECT_FALSE(request->OnStart(errorGuard));
    }

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::ALGORITHM_NEGOTIATION_FAILED);
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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(MakeCompanionProfile()));
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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(MakeCompanionProfile()));
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

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddHostBinding_001, TestSize.Level0)
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
    beginRequest.companionUserKey.userId = COMPANION_DEVICE_KEY.deviceUserId;
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

    request->HandleBeginAddHostBinding(attrInput, messageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::SUCCESS);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddHostBinding_002, TestSize.Level0)
{
    MockGuard guard;

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserKey.userId = COMPANION_DEVICE_KEY.deviceUserId;
    beginRequest.extraInfo = { 13, 14, 15, 16 };
    Attributes attrInput;
    EncodeBeginAddHostBindingRequest(beginRequest, attrInput);

    OnMessageReply messageReply = nullptr;

    ASSERT_NO_THROW(request->HandleBeginAddHostBinding(attrInput, messageReply));
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddHostBinding_003, TestSize.Level0)
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

    request->HandleBeginAddHostBinding(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddHostBinding_004, TestSize.Level0)
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
    beginRequest.companionUserKey.userId = COMPANION_DEVICE_KEY.deviceUserId;
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

    request->HandleBeginAddHostBinding(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::FAIL);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddHostBinding_001, TestSize.Level0)
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
    endRequest.companionUserKey.userId = COMPANION_DEVICE_KEY.deviceUserId;
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

    request->HandleEndAddHostBinding(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::SUCCESS);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddHostBinding_002, TestSize.Level0)
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
    endRequest.companionUserKey.userId = COMPANION_DEVICE_KEY.deviceUserId;
    endRequest.result = ResultCode::SUCCESS;
    Attributes attrInput;
    EncodeEndAddHostBindingRequest(endRequest, attrInput);
    attrInput.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(endRequest.hostDeviceKey.idType));
    attrInput.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, endRequest.hostDeviceKey.deviceId);

    OnMessageReply messageReply = nullptr;

    ASSERT_NO_THROW(request->HandleEndAddHostBinding(attrInput, messageReply));
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddHostBinding_003, TestSize.Level0)
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

    request->HandleEndAddHostBinding(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddHostBinding_004, TestSize.Level0)
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
    endRequest.companionUserKey.userId = COMPANION_DEVICE_KEY.deviceUserId;
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

    request->HandleEndAddHostBinding(attrInput, messageReply);

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

HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddHostBinding_005, TestSize.Level0)
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
    beginRequest.companionUserKey.userId = COMPANION_DEVICE_KEY.deviceUserId;
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

    request->HandleBeginAddHostBinding(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

// A local device key with an unknown user is the {-1,-1} sentinel; an announcement carrying the
// same sentinel must not pass the equality gate and start a binding for an unknown owner.
HWTEST_F(CompanionAddCompanionRequestTest, HandleBeginAddHostBinding_RejectsInvalidUserKey, TestSize.Level0)
{
    MockGuard guard;

    DeviceKey invalidUserDeviceKey = COMPANION_DEVICE_KEY;
    invalidUserDeviceKey.deviceUserId = INVALID_USER_ID;
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(invalidUserDeviceKey));

    OnMessageReply onMessageReply = [](const Attributes &) {};
    Attributes initKeyNegoRequest;
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, initKeyNegoRequest,
        std::move(onMessageReply), HOST_DEVICE_KEY);

    ErrorGuard errorGuard([](ResultCode) {});
    request->OnStart(errorGuard);

    BeginAddHostBindingRequest beginRequest;
    beginRequest.companionUserKey.userId = INVALID_USER_ID;
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

    EXPECT_CALL(guard.GetHostBindingManager(), BeginAddHostBinding(_, _)).Times(0);

    request->HandleBeginAddHostBinding(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, HandleEndAddHostBinding_005, TestSize.Level0)
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
    endRequest.companionUserKey.userId = COMPANION_DEVICE_KEY.deviceUserId;
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

    request->HandleEndAddHostBinding(attrInput, messageReply);

    EXPECT_TRUE(*replyCalled);
    EXPECT_EQ(*receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAddCompanionRequestTest, ValidateAndPinProtocol_001, TestSize.Level0)
{
    MockGuard guard;
    auto negotiateProfile = MakeCompanionProfile();

    auto callback = [](const Attributes &) {};
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, Attributes(),
        OnMessageReply(callback), HOST_DEVICE_KEY);

    InitKeyNegotiationRequest initRequest;
    initRequest.protocolId = ProtocolId::VERSION_1;

    EXPECT_EQ(request->ValidateAndPinProtocol(negotiateProfile, initRequest), ResultCode::SUCCESS);
    EXPECT_EQ(request->selectedProtocolId_, ProtocolId::VERSION_1);
}

HWTEST_F(CompanionAddCompanionRequestTest, ValidateAndPinProtocol_002, TestSize.Level0)
{
    MockGuard guard;
    auto negotiateProfile = MakeCompanionProfile();

    auto callback = [](const Attributes &) {};
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, Attributes(),
        OnMessageReply(callback), HOST_DEVICE_KEY);

    InitKeyNegotiationRequest initRequest;
    initRequest.protocolId = UNSUPPORTED_PROTOCOL_ID;

    EXPECT_EQ(request->ValidateAndPinProtocol(negotiateProfile, initRequest), ResultCode::PROTOCOL_NEGOTIATION_FAILED);
}

HWTEST_F(CompanionAddCompanionRequestTest, ValidateAndPinProtocol_003, TestSize.Level0)
{
    MockGuard guard;
    auto negotiateProfile = MakeCompanionProfile();

    auto callback = [](const Attributes &) {};
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, Attributes(),
        OnMessageReply(callback), HOST_DEVICE_KEY);

    InitKeyNegotiationRequest initRequest;

    EXPECT_EQ(request->ValidateAndPinProtocol(negotiateProfile, initRequest), ResultCode::SUCCESS);
    EXPECT_EQ(request->selectedProtocolId_, ProtocolId::VERSION_1);
}

// A legacy host (no negotiated protocol on the wire) decodes as the pre-baseline default
// VERSION_1, so a multi-protocol companion pins itself to that default and enrolls it — the
// same single-value echo a legacy host strict-compares.
HWTEST_F(CompanionAddCompanionRequestTest, ValidateAndPinProtocol_004, TestSize.Level0)
{
    MockGuard guard;
    LocalDeviceProfile negotiateProfile = MakeCompanionProfile();
    constexpr ProtocolId PROTOCOL_VERSION_2 = static_cast<ProtocolId>(2);
    negotiateProfile.protocols = { PROTOCOL_VERSION_2, ProtocolId::VERSION_1 };

    auto callback = [](const Attributes &) {};
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, Attributes(),
        OnMessageReply(callback), HOST_DEVICE_KEY);

    InitKeyNegotiationRequest initRequest;

    EXPECT_EQ(request->ValidateAndPinProtocol(negotiateProfile, initRequest), ResultCode::SUCCESS);
    EXPECT_EQ(request->selectedProtocolId_, ProtocolId::VERSION_1);
}

HWTEST_F(CompanionAddCompanionRequestTest, ValidateAndPinProtocol_005, TestSize.Level0)
{
    MockGuard guard;
    LocalDeviceProfile negotiateProfile = MakeCompanionProfile();
    constexpr ProtocolId PROTOCOL_VERSION_2 = static_cast<ProtocolId>(2);
    negotiateProfile.protocols = { PROTOCOL_VERSION_2 };

    auto callback = [](const Attributes &) {};
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, Attributes(),
        OnMessageReply(callback), HOST_DEVICE_KEY);

    InitKeyNegotiationRequest initRequest;

    EXPECT_EQ(request->ValidateAndPinProtocol(negotiateProfile, initRequest), ResultCode::PROTOCOL_NEGOTIATION_FAILED);
}

// An explicit INVALID(0) on the wire is a host bug, not a legacy host (those omit the field):
// fail closed instead of treating it as the pre-baseline default.
HWTEST_F(CompanionAddCompanionRequestTest, ValidateAndPinProtocol_006, TestSize.Level0)
{
    MockGuard guard;
    auto negotiateProfile = MakeCompanionProfile();

    auto callback = [](const Attributes &) {};
    auto request = std::make_shared<CompanionAddCompanionRequest>(CONNECTION_NAME, Attributes(),
        OnMessageReply(callback), HOST_DEVICE_KEY);

    InitKeyNegotiationRequest initRequest;
    initRequest.protocolId = ProtocolId::INVALID;

    EXPECT_EQ(request->ValidateAndPinProtocol(negotiateProfile, initRequest), ResultCode::PROTOCOL_NEGOTIATION_FAILED);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
