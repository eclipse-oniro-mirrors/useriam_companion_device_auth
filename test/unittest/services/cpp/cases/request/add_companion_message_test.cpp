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

#include "add_companion_message.h"
#include "attributes.h"
#include "common_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class AddCompanionMessageTest : public Test {
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

HWTEST_F(AddCompanionMessageTest, EncodeDecodeInitKeyNegotiationRequest_001, TestSize.Level0)
{
    InitKeyNegotiationRequest request = { .hostDeviceKey = hostDeviceKey_, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeInitKeyNegotiationRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto decoded = DecodeInitKeyNegotiationRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->hostDeviceKey.idType, request.hostDeviceKey.idType);
    EXPECT_EQ(decoded->hostDeviceKey.deviceId, request.hostDeviceKey.deviceId);
    EXPECT_EQ(decoded->hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decoded->extraInfo, request.extraInfo);
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeInitKeyNegotiationRequest_002, TestSize.Level0)
{
    InitKeyNegotiationRequest request = { .hostDeviceKey = hostDeviceKey_, .extraInfo = {} };

    Attributes attributes;
    bool encodeResult = EncodeInitKeyNegotiationRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto decoded = DecodeInitKeyNegotiationRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->extraInfo.empty());
}

HWTEST_F(AddCompanionMessageTest, DecodeInitKeyNegotiationRequest_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeInitKeyNegotiationRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, DecodeInitKeyNegotiationRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, 100);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, 1);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "test");

    auto decoded = DecodeInitKeyNegotiationRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeInitKeyNegotiationReply_001, TestSize.Level0)
{
    InitKeyNegotiationReply reply = { .result = ResultCode::SUCCESS, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeInitKeyNegotiationReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeInitKeyNegotiationReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::SUCCESS);
    EXPECT_EQ(decoded->extraInfo, reply.extraInfo);
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeInitKeyNegotiationReply_002, TestSize.Level0)
{
    InitKeyNegotiationReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeInitKeyNegotiationReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeInitKeyNegotiationReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::GENERAL_ERROR);
    EXPECT_TRUE(decoded->extraInfo.empty());
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeInitKeyNegotiationReply_003, TestSize.Level0)
{
    InitKeyNegotiationReply reply = { .result = ResultCode::SUCCESS, .extraInfo = {} };

    Attributes attributes;
    bool encodeResult = EncodeInitKeyNegotiationReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeInitKeyNegotiationReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::SUCCESS);
    EXPECT_TRUE(decoded->extraInfo.empty());
}

HWTEST_F(AddCompanionMessageTest, DecodeInitKeyNegotiationReply_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeInitKeyNegotiationReply(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, DecodeInitKeyNegotiationReply_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    auto decoded = DecodeInitKeyNegotiationReply(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeBeginAddHostBindingRequest_001, TestSize.Level0)
{
    BeginAddHostBindingRequest request = { .companionUserId = companionUserId_, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeBeginAddHostBindingRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeBeginAddHostBindingRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->companionUserId, request.companionUserId);
    EXPECT_EQ(decoded->extraInfo, request.extraInfo);
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeBeginAddHostBindingRequest_002, TestSize.Level0)
{
    BeginAddHostBindingRequest request = { .companionUserId = companionUserId_, .extraInfo = {} };

    Attributes attributes;
    bool encodeResult = EncodeBeginAddHostBindingRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeBeginAddHostBindingRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->companionUserId, request.companionUserId);
    EXPECT_TRUE(decoded->extraInfo.empty());
}

HWTEST_F(AddCompanionMessageTest, DecodeBeginAddHostBindingRequest_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeBeginAddHostBindingRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, DecodeBeginAddHostBindingRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserId_);

    auto decoded = DecodeBeginAddHostBindingRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeBeginAddHostBindingReply_001, TestSize.Level0)
{
    BeginAddHostBindingReply reply = { .result = ResultCode::SUCCESS, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeBeginAddHostBindingReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeBeginAddHostBindingReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::SUCCESS);
    EXPECT_EQ(decoded->extraInfo, reply.extraInfo);
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeBeginAddHostBindingReply_002, TestSize.Level0)
{
    BeginAddHostBindingReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeBeginAddHostBindingReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeBeginAddHostBindingReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::GENERAL_ERROR);
    EXPECT_TRUE(decoded->extraInfo.empty());
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeBeginAddHostBindingReply_003, TestSize.Level0)
{
    BeginAddHostBindingReply reply = { .result = ResultCode::SUCCESS, .extraInfo = {} };

    Attributes attributes;
    bool encodeResult = EncodeBeginAddHostBindingReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeBeginAddHostBindingReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::SUCCESS);
    EXPECT_TRUE(decoded->extraInfo.empty());
}

HWTEST_F(AddCompanionMessageTest, DecodeBeginAddHostBindingReply_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeBeginAddHostBindingReply(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, DecodeBeginAddHostBindingReply_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    auto decoded = DecodeBeginAddHostBindingReply(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeEndAddHostBindingRequest_001, TestSize.Level0)
{
    EndAddHostBindingRequest request = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .result = ResultCode::SUCCESS };

    Attributes attributes;
    bool encodeResult = EncodeEndAddHostBindingRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto decoded = DecodeEndAddHostBindingRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->hostDeviceKey.idType, request.hostDeviceKey.idType);
    EXPECT_EQ(decoded->hostDeviceKey.deviceId, request.hostDeviceKey.deviceId);
    EXPECT_EQ(decoded->hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decoded->companionUserId, request.companionUserId);
    EXPECT_EQ(decoded->result, request.result);
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeEndAddHostBindingRequest_002, TestSize.Level0)
{
    EndAddHostBindingRequest request = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .result = ResultCode::GENERAL_ERROR };

    Attributes attributes;
    bool encodeResult = EncodeEndAddHostBindingRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto decoded = DecodeEndAddHostBindingRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::GENERAL_ERROR);
}

HWTEST_F(AddCompanionMessageTest, DecodeEndAddHostBindingRequest_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeEndAddHostBindingRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, DecodeEndAddHostBindingRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, 100);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, 1);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "test");

    auto decoded = DecodeEndAddHostBindingRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, DecodeEndAddHostBindingRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, 100);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, 1);
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "test");
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserId_);

    auto decoded = DecodeEndAddHostBindingRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AddCompanionMessageTest, EncodeDecodeEndAddHostBindingReply_001, TestSize.Level0)
{
    EndAddHostBindingReply reply = { .result = ResultCode::SUCCESS };

    Attributes attributes;
    bool encodeResult = EncodeEndAddHostBindingReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeEndAddHostBindingReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::SUCCESS);
}

HWTEST_F(AddCompanionMessageTest, DecodeEndAddHostBindingReply_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeEndAddHostBindingReply(attributes);
    EXPECT_FALSE(decoded.has_value());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
