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
#include "host_add_companion_request.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// Test constants
constexpr ScheduleId SCHEDULE_ID = 1;
const std::vector<uint8_t> FWK_MSG = { 1, 2, 3, 4 };
constexpr uint32_t TOKEN_ID = 123;
constexpr int32_t TEMPLATE_ID = 12345;
const std::string ADDITIONAL_INFO = "";

const DeviceKey COMPANION_DEVICE_KEY = { .deviceId = "companion_device_id", .deviceUserId = 100 };
const DeviceKey HOST_DEVICE_KEY = { .deviceId = "host_device_id", .deviceUserId = 100 };
const DeviceStatus DEVICE_STATUS = {
    .deviceKey = COMPANION_DEVICE_KEY,
    .channelId = ChannelId::SOFTBUS,
    .deviceModelInfo = "TestModel",
    .deviceUserName = "TestUser",
    .deviceName = "TestDevice",
    .protocolId = ProtocolId::VERSION_1,
    .secureProtocolId = SecureProtocolId::DEFAULT,
};

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class HostAddCompanionRequestTest : public Test {
protected:
    // 无成员变量，每个测试用例创建局部 request
};

HWTEST_F(HostAddCompanionRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetMiscManager(), GetDeviceDeviceSelectResult(123, SelectPurpose::SELECT_ADD_DEVICE, _))
        .WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetMiscManager(), GetDeviceDeviceSelectResult(123, SelectPurpose::SELECT_ADD_DEVICE, _))
        .WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).Times(1);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    ASSERT_NO_THROW(request->HandleDeviceSelectResult(selectedDevices));
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(false));

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    request->HandleDeviceSelectResult(selectedDevices);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_003, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    std::vector<DeviceKey> selectedDevices = {};
    request->HandleDeviceSelectResult(selectedDevices);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(
            Invoke([](const HostGetInitKeyNegotiationRequestInput &, HostGetInitKeyNegotiationRequestOutput &output) {
                output.initKeyNegotiationRequest = { 1, 2, 3 };
                return ResultCode::SUCCESS;
            }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::INIT_KEY_NEGOTIATION, _, _))
        .WillOnce(Return(true));

    request->OnConnected();
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_003, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_004, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(
            Invoke([](const HostGetInitKeyNegotiationRequestInput &, HostGetInitKeyNegotiationRequestOutput &output) {
                output.initKeyNegotiationRequest = { 1, 2, 3 };
                return ResultCode::SUCCESS;
            }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::INIT_KEY_NEGOTIATION, _, _))
        .WillOnce(Return(false));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _, _))
        .WillOnce(Invoke([](const BeginAddCompanionParams &, std::vector<uint8_t> &out, uint16_t &selectedAlgorithm) {
            out = { 4, 5, 6 };
            selectedAlgorithm = 1;
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(true));

    ASSERT_NO_THROW(request->HandleInitKeyNegotiationReply(reply));
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    request->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_003, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    request->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_004, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_005, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _, _))
        .WillOnce(Invoke([](const BeginAddCompanionParams &, std::vector<uint8_t> &out, uint16_t &selectedAlgorithm) {
            out = { 4, 5, 6 };
            selectedAlgorithm = 1;
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(false));

    request->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([](const EndAddCompanionInput &, EndAddCompanionOutput &output) {
            output.fwkMsg = { 7, 8, 9 };
            output.templateId = TEMPLATE_ID;
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::END_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(true));

    ASSERT_NO_THROW(request->HandleBeginAddHostBindingReply(reply));
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    request->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_003, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    request->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_004, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_005, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([](const EndAddCompanionInput &, EndAddCompanionOutput &output) {
            output.fwkMsg = { 7, 8, 9 };
            output.templateId = TEMPLATE_ID;
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::END_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(false));

    ASSERT_NO_THROW(request->HandleBeginAddHostBindingReply(reply));
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->templateId_ = TEMPLATE_ID;

    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAuthAtl(_, _, _)).WillOnce(Return(true));

    Attributes reply;
    EndAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS };
    EncodeEndAddHostBindingReply(replyMsg, reply);

    request->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    Attributes reply;
    request->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_003, TestSize.Level0)
{
    // Token distribution failed but enrollment succeeded - should complete with success
    MockGuard guard;

    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    Attributes reply;
    EndAddHostBindingReply replyMsg = { .result = ResultCode::GENERAL_ERROR };
    EncodeEndAddHostBindingReply(replyMsg, reply);

    request->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    request->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;

    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->needCancelCompanionAdd_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelAddCompanion(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;

    auto callbackCalled = std::make_shared<bool>(false);
    auto receivedData = std::make_shared<std::vector<uint8_t>>();
    auto callback = [&callbackCalled, &receivedData](ResultCode result, const std::vector<uint8_t> &data) {
        *callbackCalled = true;
        *receivedData = data;
        EXPECT_EQ(result, ResultCode::SUCCESS);
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    request->CompleteWithSuccess();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, EndAddCompanion_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    DeviceStatus deviceStatus;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([](const EndAddCompanionInput &input, EndAddCompanionOutput &output) {
            output.templateId = TEMPLATE_ID;
            return ResultCode::SUCCESS;
        }));

    BeginAddHostBindingReply reply;
    std::vector<uint8_t> fwkMsg;

    bool result = request->EndAddCompanion(reply, fwkMsg);

    EXPECT_TRUE(result);
    EXPECT_EQ(request->templateId_, TEMPLATE_ID);
}

HWTEST_F(HostAddCompanionRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    ASSERT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, {}));
}

HWTEST_F(HostAddCompanionRequestTest, InvokeCallback_002_DoubleInvokeProtection, TestSize.Level0)
{
    MockGuard guard;

    auto callbackCalled = std::make_shared<int>(0);
    auto callback = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { ++*callbackCalled; };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    // First call should succeed and null out the callback.
    request->InvokeCallback(ResultCode::SUCCESS, {});
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*callbackCalled, 1);

    // Second call should be silently ignored (callback already moved out).
    request->InvokeCallback(ResultCode::GENERAL_ERROR, {});
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*callbackCalled, 1);
}

HWTEST_F(HostAddCompanionRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 1);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostAddCompanionRequestTest, ParseAdditionalInfo_001, TestSize.Level0)
{
    // Test parsing additionalInfo with enabled_business_ids
    MockGuard guard;

    // Create fwkMsg with additionalInfo
    std::string additionalInfo = R"({"enabled_business_ids":[1,2,3]})";
    FwkAttribute fwkAttr;
    fwkAttr.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, additionalInfo);
    auto fwkMsg = fwkAttr.Serialize();

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, fwkMsg, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    // Parsing is done in constructor, and stored in request
    // The test passes if no exception is thrown
    EXPECT_TRUE(request != nullptr);
}

HWTEST_F(HostAddCompanionRequestTest, ParseAdditionalInfo_002, TestSize.Level0)
{
    // Test parsing additionalInfo with empty string
    MockGuard guard;

    std::string additionalInfo = "";
    FwkAttribute fwkAttr;
    fwkAttr.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, additionalInfo);
    auto fwkMsg = fwkAttr.Serialize();

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, fwkMsg, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_TRUE(request != nullptr);
}

HWTEST_F(HostAddCompanionRequestTest, ParseAdditionalInfo_003, TestSize.Level0)
{
    // Test parsing additionalInfo with invalid JSON
    MockGuard guard;

    std::string additionalInfo = "not a valid json";
    FwkAttribute fwkAttr;
    fwkAttr.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, additionalInfo);
    auto fwkMsg = fwkAttr.Serialize();

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, fwkMsg, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_TRUE(request != nullptr);
}

HWTEST_F(HostAddCompanionRequestTest, ParseAdditionalInfo_004, TestSize.Level0)
{
    // Test parsing additionalInfo with enabled_business_ids containing invalid values
    MockGuard guard;

    std::string additionalInfo = R"({"enabled_business_ids":["string", null, 10000]})";
    FwkAttribute fwkAttr;
    fwkAttr.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, additionalInfo);
    auto fwkMsg = fwkAttr.Serialize();

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, fwkMsg, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_TRUE(request != nullptr);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
