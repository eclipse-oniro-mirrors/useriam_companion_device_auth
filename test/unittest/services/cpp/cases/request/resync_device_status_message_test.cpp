/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "resync_device_status_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_200 = 200;

class RequestDeviceResyncMessageTest : public Test {
protected:
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = INT32_200 };
};

void InjectSrcIdentifier(const DeviceKey &deviceKey, Attributes &attributes)
{
    // The message router injects these from the authenticated connection in production.
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(deviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, deviceKey.deviceId);
}

HWTEST_F(RequestDeviceResyncMessageTest, EncodeRequestDeviceResyncRequest_001, TestSize.Level0)
{
    RequestDeviceResyncRequest request = { .companionDeviceKey = companionDeviceKey_ };

    Attributes attributes;
    EncodeRequestDeviceResyncRequest(request, attributes);
    InjectSrcIdentifier(companionDeviceKey_, attributes);

    auto result = DecodeRequestDeviceResyncRequest(attributes);
    ASSERT_TRUE(result.has_value());
    RequestDeviceResyncRequest decoded = result.value();

    EXPECT_EQ(decoded.companionDeviceKey.idType, request.companionDeviceKey.idType);
    EXPECT_EQ(decoded.companionDeviceKey.deviceId, request.companionDeviceKey.deviceId);
    EXPECT_EQ(decoded.companionDeviceKey.deviceUserId, request.companionDeviceKey.deviceUserId);
}

HWTEST_F(RequestDeviceResyncMessageTest, DecodeRequestDeviceResyncRequest_001, TestSize.Level0)
{
    Attributes attributes;

    auto result = DecodeRequestDeviceResyncRequest(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(RequestDeviceResyncMessageTest, DecodeRequestDeviceResyncRequest_002, TestSize.Level0)
{
    // Missing SRC_IDENTIFIER (empty device id) -> decode fails.
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionDeviceKey_.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(companionDeviceKey_.idType));

    auto result = DecodeRequestDeviceResyncRequest(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(RequestDeviceResyncMessageTest, DecodeRequestDeviceResyncRequest_003, TestSize.Level0)
{
    // Missing COMPANION_USER_ID -> decode fails.
    Attributes attributes;
    InjectSrcIdentifier(companionDeviceKey_, attributes);

    auto result = DecodeRequestDeviceResyncRequest(attributes);
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(RequestDeviceResyncMessageTest, EncodeRequestDeviceResyncReply_001, TestSize.Level0)
{
    RequestDeviceResyncReply reply = { .result = ResultCode::SUCCESS };

    Attributes attributes;
    EncodeRequestDeviceResyncReply(reply, attributes);

    auto result = DecodeRequestDeviceResyncReply(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->result, reply.result);
}

HWTEST_F(RequestDeviceResyncMessageTest, EncodeRequestDeviceResyncReply_002, TestSize.Level0)
{
    RequestDeviceResyncReply reply = { .result = ResultCode::GENERAL_ERROR };

    Attributes attributes;
    EncodeRequestDeviceResyncReply(reply, attributes);

    auto result = DecodeRequestDeviceResyncReply(attributes);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->result, reply.result);
}

HWTEST_F(RequestDeviceResyncMessageTest, DecodeRequestDeviceResyncReply_001, TestSize.Level0)
{
    Attributes attributes;

    auto result = DecodeRequestDeviceResyncReply(attributes);
    EXPECT_FALSE(result.has_value());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
