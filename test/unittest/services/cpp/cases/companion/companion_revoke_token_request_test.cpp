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

#include "companion_revoke_token_request.h"
#include "revoke_token_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// 测试数据常量
constexpr int32_t COMPANION_USER_ID = 200;
const DeviceKey HOST_DEVICE_KEY = { .deviceId = "host_device_id", .deviceUserId = 100 };
const std::string REASON = "unknown";

class CompanionRevokeTokenRequestTest : public Test {
protected:
    // 无成员变量，每个测试用例创建局部 request
};

HWTEST_F(CompanionRevokeTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    ASSERT_NO_THROW(request->OnConnected());
}

HWTEST_F(CompanionRevokeTokenRequestTest, SendRevokeTokenRequest_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);
    request->peerDeviceKey_ = std::nullopt;
    ASSERT_NO_THROW(request->SendRevokeTokenRequest());
}

HWTEST_F(CompanionRevokeTokenRequestTest, SendRevokeTokenRequest_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    ASSERT_NO_THROW(request->SendRevokeTokenRequest());
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);

    Attributes message;
    RevokeTokenReply reply = { .result = ResultCode::SUCCESS };
    EncodeRevokeTokenReply(reply, message);

    ASSERT_NO_THROW(request->HandleRevokeTokenReply(message));
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);

    Attributes message;
    ASSERT_NO_THROW(request->HandleRevokeTokenReply(message));
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_003, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);

    Attributes message;
    RevokeTokenReply reply = { .result = ResultCode::GENERAL_ERROR };
    EncodeRevokeTokenReply(reply, message);

    ASSERT_NO_THROW(request->HandleRevokeTokenReply(message));
}

HWTEST_F(CompanionRevokeTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);

    EXPECT_EQ(request->GetMaxConcurrency(), 10);
}

HWTEST_F(CompanionRevokeTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_REVOKE_TOKEN_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(CompanionRevokeTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    auto request = std::make_shared<CompanionRevokeTokenRequest>(COMPANION_USER_ID, HOST_DEVICE_KEY, REASON);

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
