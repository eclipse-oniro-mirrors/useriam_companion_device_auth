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
#include "remove_host_binding_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class RemoveHostBindingMessageTest : public Test {
public:
protected:
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    int32_t companionUserId_ = 200;
    std::vector<uint8_t> extraInfo_ = { 1, 2, 3, 4, 5 };
};

HWTEST_F(RemoveHostBindingMessageTest, EncodeDecodeRemoveHostBindingRequest_001, TestSize.Level0)
{
    RemoveHostBindingRequest request = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };

    Attributes attributes;
    EncodeRemoveHostBindingRequest(request, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto decoded = DecodeRemoveHostBindingRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->hostDeviceKey.idType, request.hostDeviceKey.idType);
    EXPECT_EQ(decoded->hostDeviceKey.deviceId, request.hostDeviceKey.deviceId);
    EXPECT_EQ(decoded->hostDeviceKey.deviceUserId, request.hostDeviceKey.deviceUserId);
    EXPECT_EQ(decoded->companionUserId, request.companionUserId);
    EXPECT_EQ(decoded->extraInfo, request.extraInfo);
}

HWTEST_F(RemoveHostBindingMessageTest, EncodeDecodeRemoveHostBindingRequest_002, TestSize.Level0)
{
    RemoveHostBindingRequest request = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = {} };

    Attributes attributes;
    EncodeRemoveHostBindingRequest(request, attributes);

    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(request.hostDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, request.hostDeviceKey.deviceId);

    auto decoded = DecodeRemoveHostBindingRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->extraInfo.empty());
}

HWTEST_F(RemoveHostBindingMessageTest, DecodeRemoveHostBindingRequest_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeRemoveHostBindingRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(RemoveHostBindingMessageTest, DecodeRemoveHostBindingRequest_002, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);

    auto decoded = DecodeRemoveHostBindingRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(RemoveHostBindingMessageTest, DecodeRemoveHostBindingRequest_003, TestSize.Level0)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserId_);

    auto decoded = DecodeRemoveHostBindingRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(RemoveHostBindingMessageTest, EncodeDecodeRemoveHostBindingReply_001, TestSize.Level0)
{
    RemoveHostBindingReply reply = { .result = ResultCode::SUCCESS };

    Attributes attributes;
    EncodeRemoveHostBindingReply(reply, attributes);

    auto decoded = DecodeRemoveHostBindingReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, reply.result);
}

HWTEST_F(RemoveHostBindingMessageTest, EncodeDecodeRemoveHostBindingReply_002, TestSize.Level0)
{
    RemoveHostBindingReply reply = { .result = ResultCode::GENERAL_ERROR };

    Attributes attributes;
    EncodeRemoveHostBindingReply(reply, attributes);

    auto decoded = DecodeRemoveHostBindingReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, reply.result);
}

HWTEST_F(RemoveHostBindingMessageTest, DecodeRemoveHostBindingReply_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeRemoveHostBindingReply(attributes);
    EXPECT_FALSE(decoded.has_value());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
