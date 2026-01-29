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

#include "host_issue_token_request.h"
#include "issue_token_message.h"
#include "mock_guard.h"

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

class HostIssueTokenRequestTest : public Test {
public:
    void CreateDefaultRequest(MockGuard &guard, std::shared_ptr<HostIssueTokenRequest> &request)
    {
        request = std::make_shared<HostIssueTokenRequest>(hostUserId_, templateId_, fwkUnlockMsg_);
    }

    int32_t hostUserId_ = 100;
    uint64_t templateId_ = 12345;
    std::vector<uint8_t> fwkUnlockMsg_ = { 1, 2, 3, 4, 5 };
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    CompanionStatus companionStatus_;
    DeviceStatus deviceStatus_ = { .deviceKey = companionDeviceKey_, .isAuthMaintainActive = true };
};

HWTEST_F(HostIssueTokenRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus_)));

    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _))
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
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _))
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
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request->OnConnected();
}

HWTEST_F(HostIssueTokenRequestTest, HostPreIssueToken_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HostPreIssueToken();
}

HWTEST_F(HostIssueTokenRequestTest, HostPreIssueToken_002, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetSecurityAgent(), HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    request->HostPreIssueToken();
}

HWTEST_F(HostIssueTokenRequestTest, SendPreIssueTokenRequest_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    std::vector<uint8_t> preIssueTokenRequest = {};
    bool result = request->SendPreIssueTokenRequest(preIssueTokenRequest);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_002, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    Attributes badMessage;
    request->HandlePreIssueTokenReply(badMessage);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_003, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    PreIssueTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = {} };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    request->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_004, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_005, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    request->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_006, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request->HandleIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_002, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    Attributes badMessage;
    request->HandleIssueTokenReply(badMessage);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_003, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    IssueTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = {} };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    request->HandleIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_004, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandleIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_005, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAtl(_, _)).WillOnce(Return(true));

    request->HandleIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, EnsureCompanionAuthMaintainActive_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    DeviceStatus deviceStatus = { .isAuthMaintainActive = false };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus)));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->EnsureCompanionAuthMaintainActive(companionDeviceKey_, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, EnsureCompanionAuthMaintainActive_002, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->EnsureCompanionAuthMaintainActive(companionDeviceKey_, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);
    request->peerDeviceKey_ = companionDeviceKey_;

    std::vector<DeviceStatus> deviceStatusList = { deviceStatus_ };
    request->HandlePeerDeviceStatusChanged(deviceStatusList);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_002, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);
    request->peerDeviceKey_ = std::nullopt;

    std::vector<DeviceStatus> deviceStatusList = { deviceStatus_ };
    request->HandlePeerDeviceStatusChanged(deviceStatusList);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_003, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);
    request->peerDeviceKey_ = hostDeviceKey_;

    DeviceStatus deviceStatus = { .deviceKey = hostDeviceKey_, .isAuthMaintainActive = false };
    std::vector<DeviceStatus> deviceStatusList = { deviceStatus_, deviceStatus };
    request->HandlePeerDeviceStatusChanged(deviceStatusList);
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);
    request->needCancelIssueToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelIssueToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_Failed_002, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);
    request->needCancelIssueToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelIssueToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_003, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);
    request->needCancelIssueToken_ = false;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelIssueToken(_)).Times(0);

    request->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    request->CompleteWithSuccess();
}

HWTEST_F(HostIssueTokenRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostIssueTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    EXPECT_EQ(request->GetMaxConcurrency(), 10);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    bool result = request->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);
    request->peerDeviceKey_ = std::nullopt;

    bool result = request->ShouldCancelOnNewRequest(RequestType::HOST_ISSUE_TOKEN_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    MockGuard guard;
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    std::shared_ptr<HostIssueTokenRequest> request;
    CreateDefaultRequest(guard, request);

    bool result = request->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
