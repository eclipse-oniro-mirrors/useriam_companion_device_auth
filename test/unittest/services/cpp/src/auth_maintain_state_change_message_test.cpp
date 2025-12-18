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

#include "auth_maintain_state_change_message.h"
#include "cda_attributes.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class AuthMaintainStateChangeMessageTest : public Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

HWTEST_F(AuthMaintainStateChangeMessageTest, EncodeDecodeAuthMaintainStateChangeRequest_001, TestSize.Level0)
{
    AuthMaintainStateChangeRequestMsg request = { .authMaintainState = true };

    Attributes attributes;
    bool encodeResult = EncodeAuthMaintainStateChangeRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeAuthMaintainStateChangeRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->authMaintainState);
}

HWTEST_F(AuthMaintainStateChangeMessageTest, EncodeDecodeAuthMaintainStateChangeRequest_002, TestSize.Level0)
{
    AuthMaintainStateChangeRequestMsg request = { .authMaintainState = false };

    Attributes attributes;
    bool encodeResult = EncodeAuthMaintainStateChangeRequest(request, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeAuthMaintainStateChangeRequest(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->authMaintainState);
}

HWTEST_F(AuthMaintainStateChangeMessageTest, DecodeAuthMaintainStateChangeRequest_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeAuthMaintainStateChangeRequest(attributes);
    EXPECT_FALSE(decoded.has_value());
}

HWTEST_F(AuthMaintainStateChangeMessageTest, EncodeDecodeAuthMaintainStateChangeReply_001, TestSize.Level0)
{
    AuthMaintainStateChangeReplyMsg reply = { .result = ResultCode::SUCCESS };

    Attributes attributes;
    bool encodeResult = EncodeAuthMaintainStateChangeReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeAuthMaintainStateChangeReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::SUCCESS);
}

HWTEST_F(AuthMaintainStateChangeMessageTest, EncodeDecodeAuthMaintainStateChangeReply_002, TestSize.Level0)
{
    AuthMaintainStateChangeReplyMsg reply = { .result = ResultCode::GENERAL_ERROR };

    Attributes attributes;
    bool encodeResult = EncodeAuthMaintainStateChangeReply(reply, attributes);
    EXPECT_TRUE(encodeResult);

    auto decoded = DecodeAuthMaintainStateChangeReply(attributes);
    EXPECT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::GENERAL_ERROR);
}

HWTEST_F(AuthMaintainStateChangeMessageTest, DecodeAuthMaintainStateChangeReply_001, TestSize.Level0)
{
    Attributes attributes;

    auto decoded = DecodeAuthMaintainStateChangeReply(attributes);
    EXPECT_FALSE(decoded.has_value());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
