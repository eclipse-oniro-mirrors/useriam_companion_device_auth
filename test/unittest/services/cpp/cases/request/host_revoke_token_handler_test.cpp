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

#include "error_guard.h"
#include "host_revoke_token_handler.h"
#include "revoke_token_message.h"

#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class HostRevokeTokenHandlerTest : public Test {
public:
    void CreateDefaultHandler()
    {
        handler_ = std::make_unique<HostRevokeTokenHandler>();
    }

protected:
    std::unique_ptr<HostRevokeTokenHandler> handler_;

    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    CompanionStatus companionStatus_;
};

HWTEST_F(HostRevokeTokenHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultHandler();
    Attributes request;
    RevokeTokenRequest revokeTokenRequest = { .hostUserId = 100, .companionDeviceKey = companionDeviceKey_ };
    EncodeRevokeTokenRequest(revokeTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(revokeTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, revokeTokenRequest.companionDeviceKey.deviceId);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAtl(_, Eq(std::nullopt))).WillOnce(Return(true));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(HostRevokeTokenHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultHandler();
    Attributes request;
    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostRevokeTokenHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultHandler();
    Attributes request;
    RevokeTokenRequest revokeTokenRequest = { .hostUserId = 100, .companionDeviceKey = companionDeviceKey_ };
    EncodeRevokeTokenRequest(revokeTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(revokeTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, revokeTokenRequest.companionDeviceKey.deviceId);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostRevokeTokenHandlerTest, HandleRequest_004, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultHandler();
    Attributes request;
    RevokeTokenRequest revokeTokenRequest = { .hostUserId = 100, .companionDeviceKey = companionDeviceKey_ };
    EncodeRevokeTokenRequest(revokeTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(revokeTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, revokeTokenRequest.companionDeviceKey.deviceId);

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAtl(_, Eq(std::nullopt))).WillOnce(Return(true));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    // Note: New implementation always returns SUCCESS after SetCompanionTokenAth
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
