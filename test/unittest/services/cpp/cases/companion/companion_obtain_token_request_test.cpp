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

#include "companion_obtain_token_request.h"
#include "obtain_token_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };
const DeviceKey HOST_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "host_device_id",
    .deviceUserId = 100 };
const std::vector<uint8_t> FWK_UNLOCK_MSG = {};
const HostBindingStatus HOST_BINDING_STATUS = {};
const uint32_t LOCK_STATE_AUTH_TYPE_VALUE = 1;

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class CompanionObtainTokenRequestTest : public Test {
protected:
};

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    ASSERT_NO_THROW(request->OnConnected());
}

HWTEST_F(CompanionObtainTokenRequestTest, OnConnected_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    ASSERT_NO_THROW(request->OnConnected());
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    ASSERT_NO_THROW(request->HandlePreObtainTokenReply(reply));
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    Attributes reply;
    ASSERT_NO_THROW(request->HandlePreObtainTokenReply(reply));
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::GENERAL_ERROR),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    ASSERT_NO_THROW(request->HandlePreObtainTokenReply(reply));
}

HWTEST_F(CompanionObtainTokenRequestTest, HandlePreObtainTokenReply_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    Attributes reply;
    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodePreObtainTokenReply(preObtainTokenReply, reply);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    ASSERT_NO_THROW(request->HandlePreObtainTokenReply(reply));
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionBeginObtainToken_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    bool result = request->CompanionBeginObtainToken(preObtainTokenReply.extraInfo);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionBeginObtainToken_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    PreObtainTokenReply preObtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(HOST_BINDING_STATUS)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    bool result = request->CompanionBeginObtainToken(preObtainTokenReply.extraInfo);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    ASSERT_NO_THROW(request->HandleObtainTokenReply(reply));
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    Attributes reply;
    ASSERT_NO_THROW(request->HandleObtainTokenReply(reply));
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::GENERAL_ERROR),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    ASSERT_NO_THROW(request->HandleObtainTokenReply(reply));
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleObtainTokenReply_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    Attributes reply;
    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    EncodeObtainTokenReply(obtainTokenReply, reply);

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->HandleObtainTokenReply(reply));
}

HWTEST_F(CompanionObtainTokenRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);
    request->needCancelObtainToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionObtainTokenRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);
    request->needCancelObtainToken_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionObtainTokenRequestTest, CompleteWithError_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);
    request->needCancelObtainToken_ = true;

    int cancelCallCount = 0;
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_))
        .WillByDefault(Invoke([&cancelCallCount](const CompanionCancelObtainTokenInput &) {
            cancelCallCount++;
            return ResultCode::SUCCESS;
        }));

    // Re-entrant terminal call must be suppressed by AcquireCompletion: the cancel SA op runs exactly once.
    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::GENERAL_ERROR));
    EXPECT_EQ(cancelCallCount, 1);
}

HWTEST_F(CompanionObtainTokenRequestTest, CompanionEndObtainToken_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    EXPECT_CALL(guard.GetHostBindingManager(), SetHostBindingTokenValid(_, _)).WillOnce(Return(true));

    ObtainTokenReply obtainTokenReply = { .result = static_cast<int32_t>(ResultCode::SUCCESS),
        .extraInfo = { 1, 2, 3 } };
    bool result = request->CompanionEndObtainToken(obtainTokenReply);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    EXPECT_EQ(request->GetMaxConcurrency(), 10);
}

HWTEST_F(CompanionObtainTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    auto peerDeviceKey = request->peerDeviceKey_;
    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_OBTAIN_TOKEN_REQUEST);
    newRequest->SetPeerDeviceKey(peerDeviceKey);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleAuthMaintainActiveChanged_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    ASSERT_NO_THROW(request->HandleAuthMaintainActiveChanged(true));
}

HWTEST_F(CompanionObtainTokenRequestTest, HandleAuthMaintainActiveChanged_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HOST_BINDING_STATUS)));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillByDefault(Return(std::make_optional(COMPANION_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), IsAuthMaintainActive()).WillByDefault(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetSecurityAgent(), CompanionBeginObtainToken(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionEndObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetSecurityAgent(), CompanionCancelObtainToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto request =
        std::make_shared<CompanionObtainTokenRequest>(HOST_DEVICE_KEY, LOCK_STATE_AUTH_TYPE_VALUE, FWK_UNLOCK_MSG);

    ASSERT_NO_THROW(request->HandleAuthMaintainActiveChanged(false));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
