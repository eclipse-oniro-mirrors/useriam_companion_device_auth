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

#include <gtest/gtest.h>

#include "attributes.h"
#include "common_message.h"
#include "revoke_token_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class RevokeTokenMessageTest : public Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }

protected:
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    int32_t hostUserId_ = 100;
};

HWTEST_F(RevokeTokenMessageTest, EncodeDecodeRevokeTokenRequest_001, TestSize.Level0)
{
    RevokeTokenRequest request = { .hostUserId = hostUserId_, .companionDeviceKey = companionDeviceKey_ };

    Attributes attributes;
    bool encodeResult = EncodeRevokeTokenRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.companionDeviceKey.deviceId);

    RevokeTokenRequest decoded;
    bool decodeResult = DecodeRevokeTokenRequest(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.hostUserId, request.hostUserId);
    EXPECT_EQ(decoded.companionDeviceKey.idType, request.companionDeviceKey.idType);
    EXPECT_EQ(decoded.companionDeviceKey.deviceId, request.companionDeviceKey.deviceId);
    EXPECT_EQ(decoded.companionDeviceKey.deviceUserId, request.companionDeviceKey.deviceUserId);
}

HWTEST_F(RevokeTokenMessageTest, DecodeRevokeTokenRequest_001, TestSize.Level0)
{
    Attributes attributes;

    RevokeTokenRequest decoded;
    bool decodeResult = DecodeRevokeTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(RevokeTokenMessageTest, DecodeRevokeTokenRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId_);

    RevokeTokenRequest decoded;
    bool decodeResult = DecodeRevokeTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(RevokeTokenMessageTest, DecodeRevokeTokenRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId_);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionDeviceKey_.idType));

    RevokeTokenRequest decoded;
    bool decodeResult = DecodeRevokeTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(RevokeTokenMessageTest, EncodeDecodeRevokeTokenReply_001, TestSize.Level0)
{
    RevokeTokenReply reply = { .result = ResultCode::SUCCESS };

    Attributes attributes;
    bool encodeResult = EncodeRevokeTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    RevokeTokenReply decoded;
    bool decodeResult = DecodeRevokeTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
}

HWTEST_F(RevokeTokenMessageTest, EncodeDecodeRevokeTokenReply_002, TestSize.Level0)
{
    RevokeTokenReply reply = { .result = ResultCode::GENERAL_ERROR };

    Attributes attributes;
    bool encodeResult = EncodeRevokeTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    RevokeTokenReply decoded;
    bool decodeResult = DecodeRevokeTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
}

HWTEST_F(RevokeTokenMessageTest, DecodeRevokeTokenReply_001, TestSize.Level0)
{
    Attributes attributes;

    RevokeTokenReply decoded;
    bool decodeResult = DecodeRevokeTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
