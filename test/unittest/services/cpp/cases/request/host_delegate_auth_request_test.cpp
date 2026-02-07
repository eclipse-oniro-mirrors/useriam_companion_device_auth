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

#include "delegate_auth_message.h"
#include "host_delegate_auth_request.h"
#include "service_common.h"
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

class HostDelegateAuthRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<HostDelegateAuthRequest>(scheduleId_, fwkMsg_, hostUserId_, templateId_,
            std::move(requestCallback_));
    }

protected:
    std::shared_ptr<HostDelegateAuthRequest> request_;

    ScheduleId scheduleId_ = 1;
    std::vector<uint8_t> fwkMsg_ = { 1, 2, 3, 4 };
    UserId hostUserId_ = 100;
    TemplateId templateId_ = 12345;
    FwkResultCallback requestCallback_ = [](ResultCode result, const std::vector<uint8_t> &fwkMsg) {};
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    CompanionStatus companionStatus_;
};

HWTEST_F(HostDelegateAuthRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .Times(AnyNumber())
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());

    ResultCode errorCode = ResultCode::SUCCESS;
    bool result = true;
    {
        ErrorGuard errorGuard([&errorCode](ResultCode code) { errorCode = code; });
        result = request_->OnStart(errorGuard);
    }

    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::SEND_DELEGATE_AUTH_RESULT, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(HostDelegateAuthRequestTest, HostBeginDelegateAuth_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::SEND_DELEGATE_AUTH_RESULT, _))
        .WillOnce(Return(nullptr));

    request_->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HostBeginDelegateAuth_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::SEND_DELEGATE_AUTH_RESULT, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HostBeginDelegateAuth_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->delegateResultSubscription_ = MakeSubscription();

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request_->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleStartDelegateAuthReply_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    StartDelegateAuthReply reply = { .result = ResultCode::SUCCESS };
    Attributes message;
    EncodeStartDelegateAuthReply(reply, message);

    request_->HandleStartDelegateAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleStartDelegateAuthReply_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    StartDelegateAuthReply reply = { .result = ResultCode::GENERAL_ERROR };
    Attributes message;
    EncodeStartDelegateAuthReply(reply, message);

    request_->HandleStartDelegateAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleStartDelegateAuthReply_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    Attributes badMessage;

    request_->HandleStartDelegateAuthReply(badMessage);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthRequest_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    SendDelegateAuthResultRequest resultRequest = { .result = ResultCode::SUCCESS, .extraInfo = { 5, 6, 7, 8 } };
    Attributes request;
    EncodeSendDelegateAuthResultRequest(resultRequest, request);

    HostEndDelegateAuthOutput output = {};
    output.fwkMsg = { 9, 10, 11 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(output), Return(ResultCode::SUCCESS)));

    std::vector<uint8_t> fwkMsg;
    bool result = request_->HandleSendDelegateAuthRequest(request, fwkMsg);

    EXPECT_TRUE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthRequest_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    Attributes badRequest;

    std::vector<uint8_t> fwkMsg;
    bool result = request_->HandleSendDelegateAuthRequest(badRequest, fwkMsg);

    EXPECT_FALSE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthRequest_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetRequestManager(), Remove(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    SendDelegateAuthResultRequest resultRequest = { .result = ResultCode::SUCCESS, .extraInfo = { 5, 6, 7, 8 } };
    Attributes request;
    EncodeSendDelegateAuthResultRequest(resultRequest, request);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    std::vector<uint8_t> fwkMsg;
    bool result = request_->HandleSendDelegateAuthRequest(request, fwkMsg);

    EXPECT_FALSE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthRequest_004, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetRequestManager(), Remove(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    SendDelegateAuthResultRequest resultRequest = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 5, 6, 7, 8 } };
    Attributes request;
    EncodeSendDelegateAuthResultRequest(resultRequest, request);

    HostEndDelegateAuthOutput output = {};
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(output), Return(ResultCode::SUCCESS)));

    std::vector<uint8_t> fwkMsg;
    bool result = request_->HandleSendDelegateAuthRequest(request, fwkMsg);

    EXPECT_FALSE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthRequestMsg_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetRequestManager(), Remove(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    SendDelegateAuthResultRequest resultRequest = { .result = ResultCode::SUCCESS, .extraInfo = { 5, 6, 7, 8 } };
    Attributes request;
    EncodeSendDelegateAuthResultRequest(resultRequest, request);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    request_->HandleSendDelegateAuthRequestMsg(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthRequestMsg_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetRequestManager(), Remove(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    Attributes badRequest;

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    request_->HandleSendDelegateAuthRequestMsg(badRequest, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->needCancelDelegateAuth_ = true;

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->needCancelDelegateAuth_ = false;

    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(0);

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, CompleteWithError_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->needCancelDelegateAuth_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(HostDelegateAuthRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    std::vector<uint8_t> callbackFwkMsg;
    request_->requestCallback_ = [&callbackCalled, &callbackResult, &callbackFwkMsg](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
        callbackFwkMsg = fwkMsg;
    };

    std::vector<uint8_t> testFwkMsg = { 1, 2, 3 };
    request_->CompleteWithSuccess(testFwkMsg);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
    EXPECT_EQ(callbackFwkMsg, testFwkMsg);
}

HWTEST_F(HostDelegateAuthRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostDelegateAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->callbackInvoked_ = true;

    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    request_->InvokeCallback(ResultCode::SUCCESS, {});

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 1);
}

HWTEST_F(HostDelegateAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_DELEGATE_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
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
