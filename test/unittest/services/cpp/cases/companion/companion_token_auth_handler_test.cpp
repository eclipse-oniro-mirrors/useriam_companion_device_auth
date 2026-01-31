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

#include "companion_token_auth_handler.h"
#include "mock_guard.h"
#include "token_auth_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionTokenAuthHandlerTest : public Test {
protected:
    std::unique_ptr<CompanionTokenAuthHandler> handler_;
    int32_t companionUserId_ = 200;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    std::vector<uint8_t> extraInfo_ = { 1, 2, 3, 4 };
    HostBindingStatus hostBindingStatus_;
};

HWTEST_F(CompanionTokenAuthHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionTokenAuthHandler>();

    Attributes request;
    TokenAuthRequest tokenAuthRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    EncodeTokenAuthRequest(tokenAuthRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(tokenAuthRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, tokenAuthRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = -1;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionTokenAuthHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionTokenAuthHandler>();

    Attributes request;
    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = -1;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionTokenAuthHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionTokenAuthHandler>();

    Attributes request;
    TokenAuthRequest tokenAuthRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    EncodeTokenAuthRequest(tokenAuthRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(tokenAuthRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, tokenAuthRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = -1;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionTokenAuthHandlerTest, HandleRequest_004, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionTokenAuthHandler>();

    Attributes request;
    TokenAuthRequest tokenAuthRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    EncodeTokenAuthRequest(tokenAuthRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(tokenAuthRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, tokenAuthRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessTokenAuth(_, _)).WillOnce(Return(ResultCode::FAIL));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = -1;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::FAIL));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
