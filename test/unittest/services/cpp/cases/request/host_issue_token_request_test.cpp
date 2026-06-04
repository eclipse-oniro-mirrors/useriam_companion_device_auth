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

#include "host_issue_token_request.h"
#include "issue_token_message.h"
#include "mock_request.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// 测试数据常量
constexpr int32_t HOST_USER_ID = 100;
constexpr uint64_t TEMPLATE_ID = 12345;
const std::vector<uint8_t> FWK_UNLOCK_MSG = { 1, 2, 3, 4, 5 };
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
const uint32_t LOCK_STATE_AUTH_TYPE_VALUE = 1;

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class HostIssueTokenRequestTest : public Test {
protected:
    // 无成员变量，每个测试用例创建局部 request
};

HWTEST_F(HostIssueTokenRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus)));

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
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

HWTEST_F(HostIssueTokenRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_005, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    CompanionStatus companionStatus;
    companionStatus.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    ASSERT_NO_THROW(request->OnConnected());
}

HWTEST_F(HostIssueTokenRequestTest, HostPreIssueToken_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->HostPreIssueToken());
}

HWTEST_F(HostIssueTokenRequestTest, HostPreIssueToken_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    ASSERT_NO_THROW(request->HostPreIssueToken());
}

HWTEST_F(HostIssueTokenRequestTest, SendPreIssueTokenRequest_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    std::vector<uint8_t> preIssueTokenRequest = {};
    bool result = request->SendPreIssueTokenRequest(preIssueTokenRequest);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    ASSERT_NO_THROW(request->HandlePreIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    Attributes badMessage;
    ASSERT_NO_THROW(request->HandlePreIssueTokenReply(badMessage));
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_003, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    PreIssueTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = {} };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    ASSERT_NO_THROW(request->HandlePreIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_004, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->HandlePreIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_005, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    ASSERT_NO_THROW(request->HandlePreIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_006, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    ASSERT_NO_THROW(request->HandlePreIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    ASSERT_NO_THROW(request->HandleIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    Attributes badMessage;
    ASSERT_NO_THROW(request->HandleIssueTokenReply(badMessage));
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_003, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    IssueTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = {} };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    ASSERT_NO_THROW(request->HandleIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_004, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->HandleIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_005, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAuthAtl(_, _, _)).WillOnce(Return(true));

    ASSERT_NO_THROW(request->HandleIssueTokenReply(message));
}

HWTEST_F(HostIssueTokenRequestTest, EnsureCompanionAuthMaintainActive_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    DeviceStatus deviceStatus = { .isAuthMaintainActive = false };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus)));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->EnsureCompanionAuthMaintainActive(COMPANION_DEVICE_KEY, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, EnsureCompanionAuthMaintainActive_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->EnsureCompanionAuthMaintainActive(COMPANION_DEVICE_KEY, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);
    request->peerDeviceKey_ = COMPANION_DEVICE_KEY;

    std::vector<DeviceStatus> deviceStatusList = { DEVICE_STATUS };
    ASSERT_NO_THROW(request->HandlePeerDeviceStatusChanged(deviceStatusList));
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);
    request->peerDeviceKey_ = std::nullopt;

    std::vector<DeviceStatus> deviceStatusList = { DEVICE_STATUS };
    ASSERT_NO_THROW(request->HandlePeerDeviceStatusChanged(deviceStatusList));
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_003, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);
    request->peerDeviceKey_ = HOST_DEVICE_KEY;

    DeviceStatus deviceStatus = { .deviceKey = HOST_DEVICE_KEY, .isAuthMaintainActive = false };
    std::vector<DeviceStatus> deviceStatusList = { DEVICE_STATUS, deviceStatus };
    ASSERT_NO_THROW(request->HandlePeerDeviceStatusChanged(deviceStatusList));
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);
    request->needCancelIssueToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelIssueToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_Failed_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);
    request->needCancelIssueToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelIssueToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_003, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);
    request->needCancelIssueToken_ = false;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelIssueToken(_)).Times(0);

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    ASSERT_NO_THROW(request->CompleteWithSuccess());
}

HWTEST_F(HostIssueTokenRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostIssueTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    EXPECT_EQ(request->GetMaxConcurrency(), 10);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    bool result = request->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);
    request->peerDeviceKey_ = std::nullopt;

    // When peerDeviceKey is nullopt, cannot determine if same device, so should not cancel
    bool result = request->ShouldCancelOnNewRequest(RequestType::HOST_ISSUE_TOKEN_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    bool result = request->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, CanStart_001, TestSize.Level0)
{
    // No previous requests, CanStart should return true
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    std::vector<std::shared_ptr<IRequest>> prevRequests;
    EXPECT_TRUE(request->CanStart(prevRequests));
}

HWTEST_F(HostIssueTokenRequestTest, CanStart_002, TestSize.Level0)
{
    // HostTokenAuthRequest on same device blocks HostIssueTokenRequest
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    auto prevReq = std::make_shared<MockIRequest>();
    prevReq->SetRequestType(RequestType::HOST_TOKEN_AUTH_REQUEST);
    prevReq->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    std::vector<std::shared_ptr<IRequest>> prevRequests = { prevReq };
    EXPECT_FALSE(request->CanStart(prevRequests));
}

HWTEST_F(HostIssueTokenRequestTest, CanStart_003, TestSize.Level0)
{
    // HostTokenAuthRequest on different device does NOT block HostIssueTokenRequest
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    auto prevReq = std::make_shared<MockIRequest>();
    prevReq->SetRequestType(RequestType::HOST_TOKEN_AUTH_REQUEST);
    prevReq->SetPeerDeviceKey(OTHER_DEVICE_KEY);

    std::vector<std::shared_ptr<IRequest>> prevRequests = { prevReq };
    EXPECT_TRUE(request->CanStart(prevRequests));
}

HWTEST_F(HostIssueTokenRequestTest, CanStart_004, TestSize.Level0)
{
    // HostTokenAuthRequest with nullopt peerDeviceKey does NOT block
    MockGuard guard;

    auto request = std::make_shared<HostIssueTokenRequest>(HOST_USER_ID, TEMPLATE_ID, LOCK_STATE_AUTH_TYPE_VALUE,
        FWK_UNLOCK_MSG, COMPANION_DEVICE_KEY);

    auto prevReq = std::make_shared<MockIRequest>();
    prevReq->SetRequestType(RequestType::HOST_TOKEN_AUTH_REQUEST);
    prevReq->SetPeerDeviceKey(std::nullopt);

    std::vector<std::shared_ptr<IRequest>> prevRequests = { prevReq };
    EXPECT_TRUE(request->CanStart(prevRequests));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
