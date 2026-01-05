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
#include "delegate_auth_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class DelegateAuthMessageTest : public Test {
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

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeStartDelegateAuthRequest_001, TestSize.Level0)
{
    StartDelegateAuthRequest request = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeStartDelegateAuthRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto decodedRequest = DecodeStartDelegateAuthRequest(attributes);
    EXPECT_TRUE(decodedRequest.has_value());
    EXPECT_EQ(decodedRequest->hostDeviceKey.idType, request.hostDeviceKey.idType);
    EXPECT_EQ(decodedRequest->hostDeviceKey.deviceId, request.hostDeviceKey.deviceId);
    EXPECT_EQ(decodedRequest->hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decodedRequest->companionUserId, request.companionUserId);
    EXPECT_EQ(decodedRequest->extraInfo, request.extraInfo);
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeStartDelegateAuthRequest_002, TestSize.Level0)
{
    Attributes attributes;

    auto decodedRequest = DecodeStartDelegateAuthRequest(attributes);
    EXPECT_FALSE(decodedRequest.has_value());
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeStartDelegateAuthRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);

    auto decodedRequest = DecodeStartDelegateAuthRequest(attributes);
    EXPECT_FALSE(decodedRequest.has_value());
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeStartDelegateAuthRequest_004, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserId_);

    auto decodedRequest = DecodeStartDelegateAuthRequest(attributes);
    EXPECT_FALSE(decodedRequest.has_value());
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeStartDelegateAuthReply_001, TestSize.Level0)
{
    StartDelegateAuthReply reply = { .result = ResultCode::SUCCESS };

    Attributes attributes;
    bool encodeResult = EncodeStartDelegateAuthReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decodedReply = DecodeStartDelegateAuthReply(attributes);
    EXPECT_TRUE(decodedReply.has_value());
    EXPECT_EQ(decodedReply->result, reply.result);
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeStartDelegateAuthReply_002, TestSize.Level0)
{
    Attributes attributes;

    auto decodedReply = DecodeStartDelegateAuthReply(attributes);
    EXPECT_FALSE(decodedReply.has_value());
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeSendDelegateAuthResultRequest_001, TestSize.Level0)
{
    SendDelegateAuthResultRequest request = { .result = ResultCode::SUCCESS, .extraInfo = extraInfo_ };

    Attributes attributes;
    bool encodeResult = EncodeSendDelegateAuthResultRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    auto decodedRequest = DecodeSendDelegateAuthResultRequest(attributes);
    EXPECT_TRUE(decodedRequest.has_value());
    EXPECT_EQ(decodedRequest->result, request.result);
    EXPECT_EQ(decodedRequest->extraInfo, request.extraInfo);
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeSendDelegateAuthResultRequest_002, TestSize.Level0)
{
    Attributes attributes;

    auto decodedRequest = DecodeSendDelegateAuthResultRequest(attributes);
    EXPECT_FALSE(decodedRequest.has_value());
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeSendDelegateAuthResultRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));

    auto decodedRequest = DecodeSendDelegateAuthResultRequest(attributes);
    EXPECT_FALSE(decodedRequest.has_value());
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeSendDelegateAuthResultReply_001, TestSize.Level0)
{
    SendDelegateAuthResultReply reply = { .result = ResultCode::SUCCESS };

    Attributes attributes;
    bool encodeResult = EncodeSendDelegateAuthResultReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decodedReply = DecodeSendDelegateAuthResultReply(attributes);
    EXPECT_TRUE(decodedReply.has_value());
    EXPECT_EQ(decodedReply->result, reply.result);
}

HWTEST_F(DelegateAuthMessageTest, EncodeDecodeSendDelegateAuthResultReply_002, TestSize.Level0)
{
    Attributes attributes;

    auto decodedReply = DecodeSendDelegateAuthResultReply(attributes);
    EXPECT_FALSE(decodedReply.has_value());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
