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

#include "companion_obtain_token_request.h"
#include "obtain_token_message.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_time_keeper.h"

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

class CompanionObtainTokenRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto hostBindingMgr =
            std::shared_ptr<IHostBindingManager>(&mockHostBindingManager_, [](IHostBindingManager *) {});
        SingletonManager::GetInstance().SetHostBindingManager(hostBindingMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        ON_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
            .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, IsAuthMaintainActive()).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeIsAuthMaintainActive(_))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockSecurityAgent_, CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
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
        request_ = std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey_, fwkUnlockMsg_);
    }

protected:
    std::shared_ptr<CompanionObtainTokenRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;

    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    std::vector<uint8_t> fwkUnlockMsg_ = {};
    HostBindingStatus hostBindingStatus_;
};

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_001, TestSize.Level0)
{
    CreateDefaultRequest();

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, IsAuthMaintainActive()).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_003, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeIsAuthMaintainActive(_)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_004, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(CompanionObtainTokenRequestTest, OnConnected_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->OnConnected();
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_001, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->HandlePreObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_002, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes reply;
    request_->HandlePreObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_003, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::GENERAL_ERROR),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    request_->HandlePreObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_004, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    request_->HandlePreObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionBeginObtainToken_001, TestSize.Level0)
{
    CreateDefaultRequest();

    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    bool result = request_->CompanionBeginObtainToken(preObtainTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionBeginObtainToken_002, TestSize.Level0)
{
    CreateDefaultRequest();

    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    bool result = request_->CompanionBeginObtainToken(preObtainTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_001, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    EXPECT_CALL(mockSecurityAgent_, CompanionEndObtainToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->HandleObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_002, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes reply;
    request_->HandleObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_003, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::GENERAL_ERROR),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    request_->HandleObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_004, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    EXPECT_CALL(mockSecurityAgent_, CompanionEndObtainToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needCancelObtainToken_ = true;

    EXPECT_CALL(mockSecurityAgent_, CompanionCancelObtainToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompleteWithError_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needCancelObtainToken_ = true;

    EXPECT_CALL(mockSecurityAgent_, CompanionCancelObtainToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionEndObtainToken_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockHostBindingManager_, SetHostBindingTokenValid(_, _)).WillOnce(Return(true));

    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    bool result = request_->CompanionEndObtainToken(obtainTokenReply);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(CompanionObtainTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();

    auto newPeerDevice = request_->peerDeviceKey_;
    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_OBTAIN_TOKEN_REQUEST, newPeerDevice, 0);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleAuthMaintainActiveChanged_001, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->HandleAuthMaintainActiveChanged(true);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleAuthMaintainActiveChanged_002, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->HandleAuthMaintainActiveChanged(false);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS