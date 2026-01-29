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

#include "adapter_manager.h"
#include "companion_delegate_auth_request.h"
#include "companion_start_delegate_auth_handler.h"
#include "delegate_auth_message.h"
#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_200 = 200;

class CompanionStartDelegateAuthHandlerTest : public Test {
protected:
    std::unique_ptr<CompanionStartDelegateAuthHandler> handler_;
    std::string connectionName_ = "test_connection";
    int32_t companionUserId_ = INT32_200;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    std::vector<uint8_t> extraInfo_ = { 1, 2, 3, 4 };
};

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionStartDelegateAuthHandler>();

    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    Attributes request;
    EncodeStartDelegateAuthRequest(startRequest, request);
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(startRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, startRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionDelegateAuthRequest(_, _, _, _))
        .WillOnce(Invoke([](const std::string &connectionName, int32_t companionUserId, const DeviceKey &hostDeviceKey,
                             const std::vector<uint8_t> &startDelegateAuthRequest) {
            return std::make_shared<CompanionDelegateAuthRequest>(connectionName, companionUserId, hostDeviceKey,
                startDelegateAuthRequest);
        }));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionStartDelegateAuthHandler>();

    Attributes request;

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionStartDelegateAuthHandler>();

    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    Attributes request;
    EncodeStartDelegateAuthRequest(startRequest, request);
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(startRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, startRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionDelegateAuthRequest(_, _, _, _)).WillOnce(Return(nullptr));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_004, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionStartDelegateAuthHandler>();

    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    Attributes request;
    EncodeStartDelegateAuthRequest(startRequest, request);
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(startRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, startRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionDelegateAuthRequest(_, _, _, _))
        .WillOnce(Invoke([](const std::string &connectionName, int32_t companionUserId, const DeviceKey &hostDeviceKey,
                             const std::vector<uint8_t> &startDelegateAuthRequest) {
            return std::make_shared<CompanionDelegateAuthRequest>(connectionName, companionUserId, hostDeviceKey,
                startDelegateAuthRequest);
        }));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(false));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_005, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionStartDelegateAuthHandler>();

    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
