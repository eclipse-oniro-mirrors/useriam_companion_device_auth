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
#include "obtain_token_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class ObtainTokenMessageTest : public Test {
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
    int32_t requestId_ = 12345;
    std::vector<uint8_t> extraInfo_ = { 1, 2, 3, 4, 5 };
};

HWTEST_F(ObtainTokenMessageTest, EncodeDecodePreObtainTokenRequest_001, TestSize.Level0)
{
    PreObtainTokenRequest request = { .hostUserId = hostUserId_,
        .companionDeviceKey = companionDeviceKey_,
        .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodePreObtainTokenRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.companionDeviceKey.deviceId);

    PreObtainTokenRequest decoded;
    bool decodeResult = DecodePreObtainTokenRequest(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.hostUserId, request.hostUserId);
    EXPECT_EQ(decoded.companionDeviceKey.idType, request.companionDeviceKey.idType);
    EXPECT_EQ(decoded.companionDeviceKey.deviceId, request.companionDeviceKey.deviceId);
    EXPECT_EQ(decoded.companionDeviceKey.deviceUserId, request.companionDeviceKey.deviceUserId);
    EXPECT_EQ(decoded.extraInfo, request.extraInfo);
}

HWTEST_F(ObtainTokenMessageTest, EncodeDecodePreObtainTokenRequest_002, TestSize.Level0)
{
    PreObtainTokenRequest request = { .hostUserId = hostUserId_,
        .companionDeviceKey = companionDeviceKey_,
        .extraInfo = {} };

    Attributes attributes;
    bool encodeResult = EncodePreObtainTokenRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.companionDeviceKey.deviceId);

    PreObtainTokenRequest decoded;
    bool decodeResult = DecodePreObtainTokenRequest(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.hostUserId, request.hostUserId);
    EXPECT_TRUE(decoded.extraInfo.empty());
}

HWTEST_F(ObtainTokenMessageTest, DecodePreObtainTokenRequest_001, TestSize.Level0)
{
    Attributes attributes;

    PreObtainTokenRequest decoded;
    bool decodeResult = DecodePreObtainTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, DecodePreObtainTokenRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId_);

    PreObtainTokenRequest decoded;
    bool decodeResult = DecodePreObtainTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, DecodePreObtainTokenRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId_);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 200);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, 1);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "test");

    PreObtainTokenRequest decoded;
    bool decodeResult = DecodePreObtainTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, EncodeDecodePreObtainTokenReply_001, TestSize.Level0)
{
    PreObtainTokenReply reply = { .result = ResultCode::SUCCESS, .requestId = requestId_, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodePreObtainTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    PreObtainTokenReply decoded;
    bool decodeResult = DecodePreObtainTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_EQ(decoded.requestId, reply.requestId);
    EXPECT_EQ(decoded.extraInfo, reply.extraInfo);
}

HWTEST_F(ObtainTokenMessageTest, EncodeDecodePreObtainTokenReply_002, TestSize.Level0)
{
    PreObtainTokenReply reply = { .result = ResultCode::GENERAL_ERROR,
        .requestId = requestId_,
        .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodePreObtainTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    PreObtainTokenReply decoded;
    bool decodeResult = DecodePreObtainTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
}

HWTEST_F(ObtainTokenMessageTest, DecodePreObtainTokenReply_001, TestSize.Level0)
{
    Attributes attributes;

    PreObtainTokenReply decoded;
    bool decodeResult = DecodePreObtainTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, DecodePreObtainTokenReply_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, ResultCode::SUCCESS);

    PreObtainTokenReply decoded;
    bool decodeResult = DecodePreObtainTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, DecodePreObtainTokenReply_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, ResultCode::SUCCESS);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_REQUEST_ID, requestId_);

    PreObtainTokenReply decoded;
    bool decodeResult = DecodePreObtainTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, EncodeDecodeObtainTokenRequest_001, TestSize.Level0)
{
    ObtainTokenRequest request = { .hostUserId = hostUserId_,
        .requestId = requestId_,
        .extraInfo = extraInfo_,
        .companionDeviceKey = companionDeviceKey_ };

    Attributes attributes;
    bool encodeResult = EncodeObtainTokenRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.companionDeviceKey.deviceId);

    ObtainTokenRequest decoded;
    bool decodeResult = DecodeObtainTokenRequest(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.hostUserId, request.hostUserId);
    EXPECT_EQ(decoded.requestId, request.requestId);
    EXPECT_EQ(decoded.extraInfo, request.extraInfo);
    EXPECT_EQ(decoded.companionDeviceKey.idType, request.companionDeviceKey.idType);
    EXPECT_EQ(decoded.companionDeviceKey.deviceId, request.companionDeviceKey.deviceId);
    EXPECT_EQ(decoded.companionDeviceKey.deviceUserId, request.companionDeviceKey.deviceUserId);
}

HWTEST_F(ObtainTokenMessageTest, EncodeDecodeObtainTokenRequest_002, TestSize.Level0)
{
    ObtainTokenRequest request = { .hostUserId = hostUserId_,
        .requestId = requestId_,
        .extraInfo = {},
        .companionDeviceKey = companionDeviceKey_ };

    Attributes attributes;
    bool encodeResult = EncodeObtainTokenRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.companionDeviceKey.deviceId);

    ObtainTokenRequest decoded;
    bool decodeResult = DecodeObtainTokenRequest(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_TRUE(decoded.extraInfo.empty());
}

HWTEST_F(ObtainTokenMessageTest, DecodeObtainTokenRequest_001, TestSize.Level0)
{
    Attributes attributes;

    ObtainTokenRequest decoded;
    bool decodeResult = DecodeObtainTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, DecodeObtainTokenRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId_);

    ObtainTokenRequest decoded;
    bool decodeResult = DecodeObtainTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, DecodeObtainTokenRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId_);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_REQUEST_ID, requestId_);

    ObtainTokenRequest decoded;
    bool decodeResult = DecodeObtainTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, DecodeObtainTokenRequest_004, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId_);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_REQUEST_ID, requestId_);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, extraInfo_);

    ObtainTokenRequest decoded;
    bool decodeResult = DecodeObtainTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, EncodeDecodeObtainTokenReply_001, TestSize.Level0)
{
    ObtainTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeObtainTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    ObtainTokenReply decoded;
    bool decodeResult = DecodeObtainTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_EQ(decoded.extraInfo, reply.extraInfo);
}

HWTEST_F(ObtainTokenMessageTest, EncodeDecodeObtainTokenReply_002, TestSize.Level0)
{
    ObtainTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeObtainTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    ObtainTokenReply decoded;
    bool decodeResult = DecodeObtainTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
}

HWTEST_F(ObtainTokenMessageTest, DecodeObtainTokenReply_001, TestSize.Level0)
{
    Attributes attributes;

    ObtainTokenReply decoded;
    bool decodeResult = DecodeObtainTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(ObtainTokenMessageTest, DecodeObtainTokenReply_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, ResultCode::SUCCESS);

    ObtainTokenReply decoded;
    bool decodeResult = DecodeObtainTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
