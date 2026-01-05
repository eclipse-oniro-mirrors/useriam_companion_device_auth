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

#include "cda_attributes.h"
#include "issue_token_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class IssueTokenMessageTest : public Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }

protected:
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    int32_t companionUserId_ = 200;
    std::vector<uint8_t> extraInfo_ = { 1, 2, 3, 4, 5 };
};

HWTEST_F(IssueTokenMessageTest, EncodeDecodePreIssueTokenRequest_001, TestSize.Level0)
{
    PreIssueTokenRequest request = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodePreIssueTokenRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    PreIssueTokenRequest decoded;
    bool decodeResult = DecodePreIssueTokenRequest(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decoded.companionUserId, request.companionUserId);
    EXPECT_EQ(decoded.extraInfo, request.extraInfo);
}

HWTEST_F(IssueTokenMessageTest, DecodePreIssueTokenRequest_001, TestSize.Level0)
{
    Attributes attributes;

    PreIssueTokenRequest decoded;
    bool decodeResult = DecodePreIssueTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, DecodePreIssueTokenRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, 100);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, 1);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "test");

    PreIssueTokenRequest decoded;
    bool decodeResult = DecodePreIssueTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, DecodePreIssueTokenRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, 100);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, 1);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "test");
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 200);

    PreIssueTokenRequest decoded;
    bool decodeResult = DecodePreIssueTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, EncodeDecodePreIssueTokenReply_001, TestSize.Level0)
{
    PreIssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodePreIssueTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    PreIssueTokenReply decoded;
    bool decodeResult = DecodePreIssueTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_EQ(decoded.extraInfo, reply.extraInfo);
}

HWTEST_F(IssueTokenMessageTest, EncodeDecodePreIssueTokenReply_002, TestSize.Level0)
{
    PreIssueTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = {} };

    Attributes attributes;
    bool encodeResult = EncodePreIssueTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    PreIssueTokenReply decoded;
    bool decodeResult = DecodePreIssueTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_TRUE(decoded.extraInfo.empty());
}

HWTEST_F(IssueTokenMessageTest, DecodePreIssueTokenReply_001, TestSize.Level0)
{
    Attributes attributes;

    PreIssueTokenReply decoded;
    bool decodeResult = DecodePreIssueTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, DecodePreIssueTokenReply_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, 0);

    PreIssueTokenReply decoded;
    bool decodeResult = DecodePreIssueTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, EncodeDecodeIssueTokenRequest_001, TestSize.Level0)
{
    IssueTokenRequest request = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeIssueTokenRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    IssueTokenRequest decoded;
    bool decodeResult = DecodeIssueTokenRequest(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decoded.companionUserId, request.companionUserId);
    EXPECT_EQ(decoded.extraInfo, request.extraInfo);
}

HWTEST_F(IssueTokenMessageTest, DecodeIssueTokenRequest_001, TestSize.Level0)
{
    Attributes attributes;

    IssueTokenRequest decoded;
    bool decodeResult = DecodeIssueTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, DecodeIssueTokenRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, 100);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, 1);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "test");

    IssueTokenRequest decoded;
    bool decodeResult = DecodeIssueTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, DecodeIssueTokenRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, 100);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, 1);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "test");
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 200);

    IssueTokenRequest decoded;
    bool decodeResult = DecodeIssueTokenRequest(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, EncodeDecodeIssueTokenReply_001, TestSize.Level0)
{
    IssueTokenReply reply = { .result = ResultCode::SUCCESS, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeIssueTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    IssueTokenReply decoded;
    bool decodeResult = DecodeIssueTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_EQ(decoded.extraInfo, reply.extraInfo);
}

HWTEST_F(IssueTokenMessageTest, EncodeDecodeIssueTokenReply_Error_002, TestSize.Level0)
{
    IssueTokenReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = {} };

    Attributes attributes;
    bool encodeResult = EncodeIssueTokenReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    IssueTokenReply decoded;
    bool decodeResult = DecodeIssueTokenReply(attributes, decoded);
    EXPECT_TRUE(decodeResult);

    EXPECT_EQ(decoded.result, reply.result);
    EXPECT_TRUE(decoded.extraInfo.empty());
}

HWTEST_F(IssueTokenMessageTest, DecodeIssueTokenReply_001, TestSize.Level0)
{
    Attributes attributes;

    IssueTokenReply decoded;
    bool decodeResult = DecodeIssueTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

HWTEST_F(IssueTokenMessageTest, DecodeIssueTokenReply_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, 0);

    IssueTokenReply decoded;
    bool decodeResult = DecodeIssueTokenReply(attributes, decoded);
    EXPECT_FALSE(decodeResult);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
