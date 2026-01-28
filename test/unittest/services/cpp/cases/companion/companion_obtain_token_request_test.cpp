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

class CompanionObtainTokenRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey_, fwkUnlockMsg_);
    }

protected:
    std::shared_ptr<CompanionObtainTokenRequest> request_;

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
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(CompanionObtainTokenRequestTest, OnConnected_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->OnConnected();
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->HandlePreObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    Attributes reply;
    request_->HandlePreObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::GENERAL_ERROR),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    request_->HandlePreObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    request_->HandlePreObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionBeginObtainToken_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    bool result = request_->CompanionBeginObtainToken(preObtainTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionBeginObtainToken_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    bool result = request_->CompanionBeginObtainToken(preObtainTokenReply);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->HandleObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    Attributes reply;
    request_->HandleObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::GENERAL_ERROR),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    request_->HandleObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleObtainTokenReply(reply);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();
    request_->needCancelObtainToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();
    request_->needCancelObtainToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionEndObtainToken_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetHostBindingManager(), SetHostBindingTokenValid(_, _)).WillOnce(Return(true));

    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    bool result = request_->CompanionEndObtainToken(obtainTokenReply);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(CompanionObtainTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    auto peerDeviceKey = request_->peerDeviceKey_;
    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_OBTAIN_TOKEN_REQUEST, peerDeviceKey, 0);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleAuthMaintainActiveChanged_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    request_->HandleAuthMaintainActiveChanged(true);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleAuthMaintainActiveChanged_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    CreateDefaultRequest();

    request_->HandleAuthMaintainActiveChanged(false);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS