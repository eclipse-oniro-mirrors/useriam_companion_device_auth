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

#include "companion_revoke_token_request.h"
#include "mock_guard.h"
#include "revoke_token_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionRevokeTokenRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<CompanionRevokeTokenRequest>(companionUserId_, hostDeviceKey_);
    }

protected:
    std::shared_ptr<CompanionRevokeTokenRequest> request_;
    int32_t companionUserId_ = 200;
    DeviceKey hostDeviceKey_ = { .deviceId = "host_device_id", .deviceUserId = 100 };
};

HWTEST_F(CompanionRevokeTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(CompanionRevokeTokenRequestTest, SendRevokeTokenRequest_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->peerDeviceKey_ = std::nullopt;
    request_->SendRevokeTokenRequest();
}

HWTEST_F(CompanionRevokeTokenRequestTest, SendRevokeTokenRequest_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request_->SendRevokeTokenRequest();
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    Attributes message;
    RevokeTokenReply reply = { .result = ResultCode::SUCCESS };
    EncodeRevokeTokenReply(reply, message);

    request_->HandleRevokeTokenReply(message);
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    Attributes message;
    request_->HandleRevokeTokenReply(message);
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    Attributes message;
    RevokeTokenReply reply = { .result = ResultCode::GENERAL_ERROR };
    EncodeRevokeTokenReply(reply, message);

    request_->HandleRevokeTokenReply(message);
}

HWTEST_F(CompanionRevokeTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(CompanionRevokeTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_REVOKE_TOKEN_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(CompanionRevokeTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
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
