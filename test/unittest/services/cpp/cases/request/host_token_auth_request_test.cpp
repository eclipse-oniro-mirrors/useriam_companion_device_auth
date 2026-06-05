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

#include "adapter_manager.h"
#include "host_token_auth_request.h"
#include "mock_request.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "token_auth_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// 测试数据常量
constexpr ScheduleId SCHEDULE_ID = 1;
const std::vector<uint8_t> FWK_MSG = { 1, 2, 3, 4 };
constexpr UserId HOST_USER_ID = 100;
constexpr TemplateId TEMPLATE_ID = 12345;
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };
const DeviceKey OTHER_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "other_companion_device_id",
    .deviceUserId = 300 };
const DeviceKey HOST_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "host_device_id",
    .deviceUserId = 100 };
const DeviceStatus DEVICE_STATUS = { .deviceKey = COMPANION_DEVICE_KEY, .isAuthMaintainActive = true };
const int32_t AUTH_INTENTION = 1;

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class HostTokenAuthRequestTest : public Test {
protected:
    // 无成员变量，每个测试用例创建局部 request
};

HWTEST_F(HostTokenAuthRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_TokenAuthAtlNull, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    // tokenAuthAtl is std::nullopt by default

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus)));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));

    ResultCode errorCode = ResultCode::SUCCESS;
    bool result = true;
    {
        ErrorGuard errorGuard([&errorCode](ResultCode code) { errorCode = code; });
        result = request->OnStart(errorGuard);
    }

    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request->OnConnected();
}

HWTEST_F(HostTokenAuthRequestTest, HostBeginTokenAuth_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HostBeginTokenAuth();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HostBeginTokenAuth_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request->HostBeginTokenAuth();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    TokenAuthReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    Attributes message;
    EncodeTokenAuthReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    Attributes message;
    request->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    TokenAuthReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 1, 2, 3, 4 } };
    Attributes message;
    EncodeTokenAuthReply(reply, message);

    request->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_004, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    TokenAuthReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    Attributes message;
    EncodeTokenAuthReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_005, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    TokenAuthReply reply = { .result = ResultCode::TOKEN_NOT_FOUND, .extraInfo = {} };
    Attributes message;
    EncodeTokenAuthReply(reply, message);

    // When TOKEN_NOT_FOUND is received, SetCompanionTokenAuthAtl with nullopt should be called to revoke token
    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAuthAtl(TEMPLATE_ID, _, _)).WillOnce(Return(true));

    request->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::TOKEN_NOT_FOUND);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_006, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    companionStatus.tokenAuthAtl = 20000;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));
    ON_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillByDefault(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request->OnStart(errorGuard));

    TokenAuthReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    Attributes message;
    EncodeTokenAuthReply(reply, message);

    // When TOKEN_VERIFY_FAILED is returned by HostEndTokenAuth (HMAC mismatch),
    // SetCompanionTokenAuthAtl with nullopt should be called to set companion ATL null
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::TOKEN_VERIFY_FAILED));
    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAuthAtl(TEMPLATE_ID, _, _)).WillOnce(Return(true));

    request->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::TOKEN_VERIFY_FAILED);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    auto callback = [&callbackCalled, &callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->needEndTokenAuth_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->needEndTokenAuth_ = false;

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).Times(0);

    request->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithSuccess_001, TestSize.Level0)
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
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    std::vector<uint8_t> testFwkMsg = { 1, 2, 3 };
    request->CompleteWithSuccess(testFwkMsg);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
    EXPECT_EQ(*callbackFwkMsg, testFwkMsg);
}

HWTEST_F(HostTokenAuthRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostTokenAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->requestCallback_ = nullptr;

    request->InvokeCallback(ResultCode::SUCCESS, {});

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostTokenAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 10);
}

HWTEST_F(HostTokenAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->peerDeviceKey_ = std::nullopt;

    // When peerDeviceKey is nullopt, cannot determine if same device, so should not cancel
    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_TOKEN_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));
    request->peerDeviceKey_ = COMPANION_DEVICE_KEY;

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_TOKEN_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, CanStart_001, TestSize.Level0)
{
    // No previous requests, CanStart should return true
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    std::vector<std::shared_ptr<IRequest>> prevRequests;
    EXPECT_TRUE(request->CanStart(prevRequests));
}

HWTEST_F(HostTokenAuthRequestTest, CanStart_002, TestSize.Level0)
{
    // HostIssueTokenRequest on same device blocks HostTokenAuthRequest
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto prevReq = std::make_shared<MockIRequest>();
    prevReq->SetRequestType(RequestType::HOST_ISSUE_TOKEN_REQUEST);
    prevReq->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    std::vector<std::shared_ptr<IRequest>> prevRequests = { prevReq };
    EXPECT_FALSE(request->CanStart(prevRequests));
}

HWTEST_F(HostTokenAuthRequestTest, CanStart_003, TestSize.Level0)
{
    // HostIssueTokenRequest on different device does NOT block HostTokenAuthRequest
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto prevReq = std::make_shared<MockIRequest>();
    prevReq->SetRequestType(RequestType::HOST_ISSUE_TOKEN_REQUEST);
    prevReq->SetPeerDeviceKey(OTHER_DEVICE_KEY);

    std::vector<std::shared_ptr<IRequest>> prevRequests = { prevReq };
    EXPECT_TRUE(request->CanStart(prevRequests));
}

HWTEST_F(HostTokenAuthRequestTest, CanStart_004, TestSize.Level0)
{
    // HostIssueTokenRequest with nullopt peerDeviceKey does NOT block
    MockGuard guard;

    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostTokenAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto prevReq = std::make_shared<MockIRequest>();
    prevReq->SetRequestType(RequestType::HOST_ISSUE_TOKEN_REQUEST);
    prevReq->SetPeerDeviceKey(std::nullopt);

    std::vector<std::shared_ptr<IRequest>> prevRequests = { prevReq };
    EXPECT_TRUE(request->CanStart(prevRequests));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
