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

constexpr ScheduleId SCHEDULE_ID = 1;
const std::vector<uint8_t> FWK_MSG = { 1, 2, 3, 4 };
constexpr UserId HOST_USER_ID = 100;
constexpr TemplateId TEMPLATE_ID = 12345;
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };
const DeviceKey HOST_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "host_device_id",
    .deviceUserId = 100 };
const int32_t AUTH_INTENTION = 1;

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class HostDelegateAuthRequestTest : public Test {
protected:
};

HWTEST_F(HostDelegateAuthRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    // Test: DELEGATE_AUTH capability not supported
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .Times(AnyNumber())
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());

    ResultCode errorCode = ResultCode::SUCCESS;
    bool result = true;
    {
        ErrorGuard errorGuard([&errorCode](ResultCode code) { errorCode = code; });
        result = request->OnStart(errorGuard);
    }

    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::SEND_DELEGATE_AUTH_RESULT, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request->OnConnected();
}

HWTEST_F(HostDelegateAuthRequestTest, HostBeginDelegateAuth_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::SEND_DELEGATE_AUTH_RESULT, _))
        .WillOnce(Return(nullptr));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HostBeginDelegateAuth_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::SEND_DELEGATE_AUTH_RESULT, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HostBeginDelegateAuth_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->delegateResultSubscription_ = MakeSubscription();

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleStartDelegateAuthReply_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    StartDelegateAuthReply reply = { .result = ResultCode::SUCCESS };
    Attributes message;
    EncodeStartDelegateAuthReply(reply, message);

    request->HandleStartDelegateAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleStartDelegateAuthReply_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    StartDelegateAuthReply reply = { .result = ResultCode::GENERAL_ERROR };
    Attributes message;
    EncodeStartDelegateAuthReply(reply, message);

    request->HandleStartDelegateAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleStartDelegateAuthReply_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    Attributes badMessage;

    request->HandleStartDelegateAuthReply(badMessage);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthResult_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    SendDelegateAuthResultRequest resultRequest = { .result = ResultCode::SUCCESS, .extraInfo = { 5, 6, 7, 8 } };
    Attributes req;
    EncodeSendDelegateAuthResultRequest(resultRequest, req);

    HostEndDelegateAuthOutput output = {};
    output.fwkMsg = { 9, 10, 11 };
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(output), Return(ResultCode::SUCCESS)));

    std::vector<uint8_t> fwkMsg;
    ResultCode result = request->HandleSendDelegateAuthResult(req, fwkMsg);

    EXPECT_EQ(result, ResultCode::SUCCESS);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthResult_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    Attributes badRequest;

    std::vector<uint8_t> fwkMsg;
    ResultCode result = request->HandleSendDelegateAuthResult(badRequest, fwkMsg);

    EXPECT_NE(result, ResultCode::SUCCESS);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthResult_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    SendDelegateAuthResultRequest resultRequest = { .result = ResultCode::SUCCESS, .extraInfo = { 5, 6, 7, 8 } };
    Attributes req;
    EncodeSendDelegateAuthResultRequest(resultRequest, req);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    std::vector<uint8_t> fwkMsg;
    ResultCode result = request->HandleSendDelegateAuthResult(req, fwkMsg);

    EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthResult_004, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    SendDelegateAuthResultRequest resultRequest = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 5, 6, 7, 8 } };
    Attributes req;
    EncodeSendDelegateAuthResultRequest(resultRequest, req);

    HostEndDelegateAuthOutput output = {};
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(output), Return(ResultCode::SUCCESS)));

    std::vector<uint8_t> fwkMsg;
    ResultCode result = request->HandleSendDelegateAuthResult(req, fwkMsg);

    EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthResultMessage_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    SendDelegateAuthResultRequest resultRequest = { .result = ResultCode::SUCCESS, .extraInfo = { 5, 6, 7, 8 } };
    Attributes req;
    EncodeSendDelegateAuthResultRequest(resultRequest, req);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    request->HandleSendDelegateAuthResultMessage(req, onMessageReply);

    EXPECT_TRUE(*replyCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, HandleSendDelegateAuthResultMessage_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_, _)).Times(AnyNumber());
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(AnyNumber());

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    Attributes badRequest;

    auto replyCalled = std::make_shared<bool>(false);
    OnMessageReply onMessageReply = [replyCalled](const Attributes &reply) {
        *replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    request->HandleSendDelegateAuthResultMessage(badRequest, onMessageReply);

    EXPECT_TRUE(*replyCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->needCancelDelegateAuth_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).WillOnce(Return(ResultCode::SUCCESS));

    request->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostDelegateAuthRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->needCancelDelegateAuth_ = false;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).Times(0);

    request->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, CompleteWithError_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->needCancelDelegateAuth_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelDelegateAuth(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostDelegateAuthRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    auto callbackFwkMsg = std::make_shared<std::vector<uint8_t>>();
    auto callback = [&callbackCalled, &callbackResult, &callbackFwkMsg](ResultCode result,
                        const std::vector<uint8_t> &fwkMsg) {
        *callbackCalled = true;
        *callbackResult = result;
        *callbackFwkMsg = fwkMsg;
    };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    std::vector<uint8_t> testFwkMsg = { 1, 2, 3 };
    request->CompleteWithSuccess(testFwkMsg);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
    EXPECT_EQ(*callbackFwkMsg, testFwkMsg);
}

HWTEST_F(HostDelegateAuthRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostDelegateAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->requestCallback_ = nullptr;

    request->InvokeCallback(ResultCode::SUCCESS, {});

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostDelegateAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 1);
}

HWTEST_F(HostDelegateAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    // Different device (nullopt) should not preempt
    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);

    // Same device should preempt
    auto newRequest2 = std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST);
    newRequest2->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    result = request->ShouldCancelOnNewRequest(*newRequest2, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostDelegateAuthRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostDelegateAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
