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

#include "mock_guard.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "add_companion_message.h"
#include "common_message.h"
#include "companion_add_companion_request.h"
#include "companion_init_key_negotiation_handler.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionInitKeyNegotiationHandlerTest : public Test {
public:
protected:
    std::unique_ptr<CompanionInitKeyNegotiationHandler> handler_;
};

HWTEST_F(CompanionInitKeyNegotiationHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;
    handler_ = std::make_unique<CompanionInitKeyNegotiationHandler>();
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    // Manually set all required DeviceKey attributes
    DeviceKey hostDeviceKey = {};
    hostDeviceKey.deviceUserId = 100;
    hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    hostDeviceKey.deviceId = "test_host_device";
    request.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey.deviceUserId);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey.deviceId);
    // Set extraInfo for InitKeyNegotiationRequest
    request.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, { 1, 2, 3, 4 });

    // Set up mock for CreateCompanionAddCompanionRequest
    std::shared_ptr<IRequest> capturedRequest;
    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionAddCompanionRequest(_, _, _, _))
        .WillOnce(Invoke([this, &capturedRequest](const std::string &connectionName, const Attributes &request,
                             OnMessageReply firstReply, const DeviceKey &deviceKey) {
            auto req = std::make_shared<CompanionAddCompanionRequest>(connectionName, request, std::move(firstReply),
                deviceKey);
            capturedRequest = req;
            return req;
        }));

    // Set up mock for RequestManager::Start
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    int replyCallCount = 0;
    int32_t lastResult = -1;
    OnMessageReply onMessageReply = [&replyCallCount, &lastResult](const Attributes &reply) {
        ++replyCallCount;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        lastResult = result;
    };

    handler_->HandleRequest(request, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Request is started asynchronously, we don't expect an immediate reply in the handler
    EXPECT_EQ(replyCallCount, 0);
}

HWTEST_F(CompanionInitKeyNegotiationHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;
    handler_ = std::make_unique<CompanionInitKeyNegotiationHandler>();
    Attributes request;

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionInitKeyNegotiationHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;
    handler_ = std::make_unique<CompanionInitKeyNegotiationHandler>();
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    // Manually set all required DeviceKey attributes
    DeviceKey hostDeviceKey = {};
    hostDeviceKey.deviceUserId = 100;
    hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    hostDeviceKey.deviceId = "test_host_device";
    request.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey.deviceUserId);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionAddCompanionRequest(_, _, _, _)).WillOnce(Return(nullptr));

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionInitKeyNegotiationHandlerTest, HandleRequest_004, TestSize.Level0)
{
    MockGuard guard;
    handler_ = std::make_unique<CompanionInitKeyNegotiationHandler>();
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    // Manually set all required DeviceKey attributes
    DeviceKey hostDeviceKey = {};
    hostDeviceKey.deviceUserId = 100;
    hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    hostDeviceKey.deviceId = "test_host_device";
    request.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey.deviceUserId);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionAddCompanionRequest(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &connectionName, const Attributes &request, OnMessageReply firstReply,
                             const DeviceKey &deviceKey) {
            return std::make_shared<CompanionAddCompanionRequest>(connectionName, request, std::move(firstReply),
                deviceKey);
        }));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(false));

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS