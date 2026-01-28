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
#include "host_obtain_token_request.h"
#include "host_pre_obtain_token_handler.h"
#include "mock_guard.h"
#include "obtain_token_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class HostPreObtainTokenHandlerTest : public Test {
public:
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
};

HWTEST_F(HostPreObtainTokenHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    EncodeCompanionDeviceKey(companionDeviceKey_, request);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &) { replyCalled = true; };

    EXPECT_CALL(guard.GetRequestFactory(), CreateHostObtainTokenRequest(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &connectionName, const Attributes &request,
                             OnMessageReply replyCallback, const DeviceKey &) {
            return std::make_shared<HostObtainTokenRequest>(connectionName, request, std::move(replyCallback),
                companionDeviceKey_);
        }));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    auto handler = std::make_unique<HostPreObtainTokenHandler>();
    handler->HandleRequest(request, onMessageReply);

    EXPECT_FALSE(replyCalled);
}

HWTEST_F(HostPreObtainTokenHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;
    Attributes request;
    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    auto handler = std::make_unique<HostPreObtainTokenHandler>();
    handler->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(HostPreObtainTokenHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    EncodeCompanionDeviceKey(companionDeviceKey_, request);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    EXPECT_CALL(guard.GetRequestFactory(), CreateHostObtainTokenRequest(_, _, _, _)).WillOnce(Return(nullptr));

    auto handler = std::make_unique<HostPreObtainTokenHandler>();
    handler->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(HostPreObtainTokenHandlerTest, HandleRequest_004, TestSize.Level0)
{
    MockGuard guard;
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    EncodeCompanionDeviceKey(companionDeviceKey_, request);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    EXPECT_CALL(guard.GetRequestFactory(), CreateHostObtainTokenRequest(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &connectionName, const Attributes &request,
                             OnMessageReply replyCallback, const DeviceKey &) {
            return std::make_shared<HostObtainTokenRequest>(connectionName, request, std::move(replyCallback),
                companionDeviceKey_);
        }));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(false));

    auto handler = std::make_unique<HostPreObtainTokenHandler>();
    handler->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS