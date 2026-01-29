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

#include "common_message.h"
#include "mock_guard.h"
#include "token_auth_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class TokenAuthMessageTest : public Test {
protected:
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    int32_t companionUserId_ = 200;
    std::vector<uint8_t> extraInfo_ = { 1, 2, 3, 4, 5 };
};

HWTEST_F(TokenAuthMessageTest, EncodeDecodeTokenAuthRequest_001, TestSize.Level0)
{
    MockGuard guard;
    TokenAuthRequest request = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };

    Attributes attributes;
    EncodeTokenAuthRequest(request, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto decodedRequest = DecodeTokenAuthRequest(attributes);
    EXPECT_TRUE(decodedRequest.has_value());
    EXPECT_EQ(decodedRequest->hostDeviceKey.idType, request.hostDeviceKey.idType);
    EXPECT_EQ(decodedRequest->hostDeviceKey.deviceId, request.hostDeviceKey.deviceId);
    EXPECT_EQ(decodedRequest->hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decodedRequest->companionUserId, request.companionUserId);
    EXPECT_EQ(decodedRequest->extraInfo, request.extraInfo);
}

HWTEST_F(TokenAuthMessageTest, EncodeDecodeTokenAuthRequest_002, TestSize.Level0)
{
    MockGuard guard;
    Attributes attributes;

    auto decodedRequest = DecodeTokenAuthRequest(attributes);
    EXPECT_FALSE(decodedRequest.has_value());
}

HWTEST_F(TokenAuthMessageTest, EncodeDecodeTokenAuthRequest_003, TestSize.Level0)
{
    MockGuard guard;
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);

    auto decodedRequest = DecodeTokenAuthRequest(attributes);
    EXPECT_FALSE(decodedRequest.has_value());
}

HWTEST_F(TokenAuthMessageTest, EncodeDecodeTokenAuthRequest_004, TestSize.Level0)
{
    MockGuard guard;
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserId_);

    auto decodedRequest = DecodeTokenAuthRequest(attributes);
    EXPECT_FALSE(decodedRequest.has_value());
}

HWTEST_F(TokenAuthMessageTest, EncodeDecodeTokenAuthReply_001, TestSize.Level0)
{
    MockGuard guard;
    TokenAuthReply reply = { .result = ResultCode::SUCCESS, .extraInfo = extraInfo_ };

    Attributes attributes;
    EncodeTokenAuthReply(reply, attributes);

    auto decodedReply = DecodeTokenAuthReply(attributes);
    EXPECT_TRUE(decodedReply.has_value());
    EXPECT_EQ(decodedReply->result, reply.result);
    EXPECT_EQ(decodedReply->extraInfo, reply.extraInfo);
}

HWTEST_F(TokenAuthMessageTest, EncodeDecodeTokenAuthReply_002, TestSize.Level0)
{
    MockGuard guard;
    Attributes attributes;

    auto decodedReply = DecodeTokenAuthReply(attributes);
    EXPECT_FALSE(decodedReply.has_value());
}

HWTEST_F(TokenAuthMessageTest, EncodeDecodeTokenAuthReply_003, TestSize.Level0)
{
    MockGuard guard;
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    auto decodedReply = DecodeTokenAuthReply(attributes);
    EXPECT_FALSE(decodedReply.has_value());
}

HWTEST_F(TokenAuthMessageTest, EncodeDecodeTokenAuthReply_004, TestSize.Level0)
{
    MockGuard guard;
    TokenAuthReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = extraInfo_ };

    Attributes attributes;
    EncodeTokenAuthReply(reply, attributes);

    auto decodedReply = DecodeTokenAuthReply(attributes);
    EXPECT_TRUE(decodedReply.has_value());
    EXPECT_EQ(decodedReply->result, reply.result);
    EXPECT_TRUE(decodedReply->extraInfo.empty());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
