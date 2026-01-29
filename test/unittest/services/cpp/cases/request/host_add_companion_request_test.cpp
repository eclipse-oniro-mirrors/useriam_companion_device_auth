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
constexpr ScheduleId SCHEDULE_ID_1 = 1;
constexpr uint32_t NUM_123 = 123;
constexpr uint32_t NUM_2 = 2;
constexpr uint32_t NUM_3 = 3;
constexpr uint32_t NUM_4 = 4;
constexpr int32_t INT32_12345 = 12345;

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class HostAddCompanionRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ =
            std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    }

protected:
    std::shared_ptr<HostAddCompanionRequest> request_;

    ScheduleId scheduleId_ = SCHEDULE_ID_1;
    std::vector<uint8_t> fwkMsg_ = { SCHEDULE_ID_1, NUM_2, NUM_3, NUM_4 };
    uint32_t tokenId_ = NUM_123;
    FwkResultCallback fwkResultCallback_ = [](ResultCode, const std::vector<uint8_t> &) {};
    DeviceKey companionDeviceKey_ = { .deviceId = "companion_device_id", .deviceUserId = 100 };
    DeviceKey hostDeviceKey_ = { .deviceId = "host_device_id", .deviceUserId = 100 };
    DeviceStatus deviceStatus_ = {
        .deviceKey = companionDeviceKey_,
        .channelId = ChannelId::SOFTBUS,
        .deviceModelInfo = "TestModel",
        .deviceUserName = "TestUser",
        .deviceName = "TestDevice",
        .protocolId = ProtocolId::VERSION_1,
        .secureProtocolId = SecureProtocolId::DEFAULT,
    };
    CompanionStatus companionStatus_ = { .companionDeviceStatus = deviceStatus_ };
};

HWTEST_F(HostAddCompanionRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetMiscManager(), GetDeviceDeviceSelectResult(123, SelectPurpose::SELECT_ADD_DEVICE, _))
        .WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetMiscManager(), GetDeviceDeviceSelectResult(123, SelectPurpose::SELECT_ADD_DEVICE, _))
        .WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).Times(1);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    std::vector<DeviceKey> selectedDevices = { companionDeviceKey_ };
    request_->HandleDeviceSelectResult(selectedDevices);
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_002, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(false));

    std::vector<DeviceKey> selectedDevices = { companionDeviceKey_ };
    request_->HandleDeviceSelectResult(selectedDevices);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_003, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));

    std::vector<DeviceKey> selectedDevices = {};
    request_->HandleDeviceSelectResult(selectedDevices);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->SetPeerDeviceKey(companionDeviceKey_);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    ASSERT_TRUE(request_->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
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

    request_->OnConnected();
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_002, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request_->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_003, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    ASSERT_TRUE(request_->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_004, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    ASSERT_TRUE(request_->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
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

    request_->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _))
        .WillOnce(Invoke([](const BeginAddCompanionParams &, std::vector<uint8_t> &out) {
            out = { 4, 5, 6 };
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(true));

    request_->HandleInitKeyNegotiationReply(reply);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_002, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    request_->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_003, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    request_->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_004, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_005, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _))
        .WillOnce(Invoke([](const BeginAddCompanionParams &, std::vector<uint8_t> &out) {
            out = { 4, 5, 6 };
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(false));

    request_->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([](const EndAddCompanionInput &, EndAddCompanionOutput &output) {
            output.fwkMsg = { 7, 8, 9 };
            return ResultCode::SUCCESS;
        }));
    CompanionStatus status;
    status.templateId = INT32_12345;
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(status)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::END_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(true));

    request_->HandleBeginAddHostBindingReply(reply);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_002, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    request_->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_003, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    request_->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_004, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_005, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->SetPeerDeviceKey(companionDeviceKey_);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([](const EndAddCompanionInput &, EndAddCompanionOutput &output) {
            output.fwkMsg = { 7, 8, 9 };
            return ResultCode::SUCCESS;
        }));
    CompanionStatus status;
    status.templateId = INT32_12345;
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(status)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::END_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(false));

    request_->HandleBeginAddHostBindingReply(reply);
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_001, TestSize.Level0)
{
    MockGuard guard;

    bool successCalled = false;
    fwkResultCallback_ = [&successCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::SUCCESS) {
            successCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->templateId_ = INT32_12345;

    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAtl(_, _)).WillOnce(Return(true));

    Attributes reply;
    EndAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS };
    EncodeEndAddHostBindingReply(replyMsg, reply);

    request_->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(successCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_002, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));

    Attributes reply;
    request_->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_003, TestSize.Level0)
{
    MockGuard guard;

    bool errorCalled = false;
    fwkResultCallback_ = [&errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));

    Attributes reply;
    EndAddHostBindingReply replyMsg = { .result = ResultCode::GENERAL_ERROR };
    EncodeEndAddHostBindingReply(replyMsg, reply);

    request_->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    bool callbackCalled = false;
    fwkResultCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &) {
        callbackCalled = true;
        EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;

    bool callbackCalled = false;
    fwkResultCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &) {
        callbackCalled = true;
        EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));
    request_->needCancelCompanionAdd_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelAddCompanion(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;

    bool callbackCalled = false;
    std::vector<uint8_t> receivedData;
    fwkResultCallback_ = [&callbackCalled, &receivedData](ResultCode result, const std::vector<uint8_t> &data) {
        callbackCalled = true;
        receivedData = data;
        EXPECT_EQ(result, ResultCode::SUCCESS);
    };

    request_ = std::make_shared<HostAddCompanionRequest>(scheduleId_, fwkMsg_, tokenId_, std::move(fwkResultCallback_));

    request_->CompleteWithSuccess();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, EndAddCompanion_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->SetPeerDeviceKey(companionDeviceKey_);

    DeviceStatus deviceStatus;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke(
            [](const EndAddCompanionInput &input, EndAddCompanionOutput &output) { return ResultCode::SUCCESS; }));
    CompanionStatus status;
    status.templateId = INT32_12345;
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(status)));

    BeginAddHostBindingReply reply;
    std::vector<uint8_t> fwkMsg;

    bool result = request_->EndAddCompanion(reply, fwkMsg);

    EXPECT_TRUE(result);
    EXPECT_EQ(request_->templateId_, status.templateId);
}

HWTEST_F(HostAddCompanionRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    // callbackInvoked_ was removed during refactoring - callback is moved on invocation
    request_->InvokeCallback(ResultCode::SUCCESS, {});
}

HWTEST_F(HostAddCompanionRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 1);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_DELEGATE_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
