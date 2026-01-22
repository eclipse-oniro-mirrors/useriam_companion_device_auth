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
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_time_keeper.h"
#include "mock_user_id_manager.h"

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
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto activeUserMgr = std::shared_ptr<IUserIdManager>(&mockUserIdManager_, [](IUserIdManager *) {});
        SingletonManager::GetInstance().SetUserIdManager(activeUserMgr);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;

        ON_CALL(mockCompanionManager_, GetCompanionStatus(_))
            .WillByDefault(Return(std::make_optional(companionStatus_)));
        ON_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_))
            .WillByDefault(Return(std::make_optional(deviceStatus_)));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
            .WillByDefault(Return(std::make_optional(SecureProtocolId::DEFAULT)));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(hostDeviceKey_)));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_))
            .WillByDefault(Return(
                std::make_optional(DeviceStatus { .deviceKey = companionDeviceKey_, .isAuthMaintainActive = true })));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockSecurityAgent_, HostPreIssueToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostBeginIssueToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostEndIssueToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostCancelIssueToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    }

    void TearDown() override
    {
        request_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

    void CreateDefaultRequest()
    {
        request_ = std::make_shared<HostIssueTokenRequest>(hostUserId_, templateId_, fwkUnlockMsg_);
    }

protected:
    std::shared_ptr<HostIssueTokenRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockUserIdManager> mockUserIdManager_;
    NiceMock<MockMiscManager> mockMiscManager_;

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
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_003, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_004, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnStart_005, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockSecurityAgent_, HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(HostIssueTokenRequestTest, HostPreIssueToken_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockSecurityAgent_, HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HostPreIssueToken();
}

HWTEST_F(HostIssueTokenRequestTest, HostPreIssueToken_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockSecurityAgent_, HostPreIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->HostPreIssueToken();
}

HWTEST_F(HostIssueTokenRequestTest, SendPreIssueTokenRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    std::vector<uint8_t> preIssueTokenRequest = {};
    bool result = request_->SendPreIssueTokenRequest(preIssueTokenRequest);

    EXPECT_TRUE(result);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_001, TestSize.Level0)
{
    CreateDefaultRequest();

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(mockSecurityAgent_, HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_002, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes badMessage;
    request_->HandlePreIssueTokenReply(badMessage);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_003, TestSize.Level0)
{
    CreateDefaultRequest();

    PreIssueTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = {} };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    request_->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_004, TestSize.Level0)
{
    CreateDefaultRequest();

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(mockSecurityAgent_, HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_005, TestSize.Level0)
{
    CreateDefaultRequest();

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(mockSecurityAgent_, HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePreIssueTokenReply_006, TestSize.Level0)
{
    CreateDefaultRequest();

    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodePreIssueTokenReply(reply, message);

    EXPECT_CALL(mockSecurityAgent_, HostBeginIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->HandlePreIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_001, TestSize.Level0)
{
    CreateDefaultRequest();

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(mockSecurityAgent_, HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->HandleIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_002, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes badMessage;
    request_->HandleIssueTokenReply(badMessage);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_003, TestSize.Level0)
{
    CreateDefaultRequest();

    IssueTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = {} };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    request_->HandleIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_004, TestSize.Level0)
{
    CreateDefaultRequest();

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(mockSecurityAgent_, HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, HandleIssueTokenReply_005, TestSize.Level0)
{
    CreateDefaultRequest();

    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3 } };
    Attributes message;
    EncodeIssueTokenReply(reply, message);

    EXPECT_CALL(mockSecurityAgent_, HostEndIssueToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCompanionManager_, SetCompanionTokenAtl(_, _)).WillOnce(Return(true));

    request_->HandleIssueTokenReply(message);
}

HWTEST_F(HostIssueTokenRequestTest, EnsureCompanionAuthMaintainActive_001, TestSize.Level0)
{
    CreateDefaultRequest();

    DeviceStatus deviceStatus = { .isAuthMaintainActive = false };
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus)));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->EnsureCompanionAuthMaintainActive(companionDeviceKey_, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, EnsureCompanionAuthMaintainActive_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->EnsureCompanionAuthMaintainActive(companionDeviceKey_, errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->peerDeviceKey_ = companionDeviceKey_;

    std::vector<DeviceStatus> deviceStatusList = { deviceStatus_ };
    request_->HandlePeerDeviceStatusChanged(deviceStatusList);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->peerDeviceKey_ = std::nullopt;

    std::vector<DeviceStatus> deviceStatusList = { deviceStatus_ };
    request_->HandlePeerDeviceStatusChanged(deviceStatusList);
}

HWTEST_F(HostIssueTokenRequestTest, HandlePeerDeviceStatusChanged_003, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->peerDeviceKey_ = hostDeviceKey_;

    DeviceStatus deviceStatus = { .deviceKey = hostDeviceKey_, .isAuthMaintainActive = false };
    std::vector<DeviceStatus> deviceStatusList = { deviceStatus_, deviceStatus };
    request_->HandlePeerDeviceStatusChanged(deviceStatusList);
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = true;

    EXPECT_CALL(mockSecurityAgent_, HostCancelIssueToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_Failed_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = true;

    EXPECT_CALL(mockSecurityAgent_, HostCancelIssueToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithError_003, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needCancelIssueToken_ = false;

    EXPECT_CALL(mockSecurityAgent_, HostCancelIssueToken(_)).Times(0);

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostIssueTokenRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->CompleteWithSuccess();
}

HWTEST_F(HostIssueTokenRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostIssueTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->peerDeviceKey_ = std::nullopt;

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ISSUE_TOKEN_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostIssueTokenRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
