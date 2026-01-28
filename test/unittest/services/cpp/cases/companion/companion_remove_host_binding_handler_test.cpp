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

#include "companion_remove_host_binding_handler.h"
#include "error_guard.h"
#include "remove_host_binding_message.h"

#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_200 = 200;

class CompanionRemoveHostBindingHandlerTest : public Test {
protected:
    std::unique_ptr<CompanionRemoveHostBindingHandler> handler_;

    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
};

HWTEST_F(CompanionRemoveHostBindingHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), RemoveHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));

    handler_ = std::make_unique<CompanionRemoveHostBindingHandler>();

    Attributes request;
    RemoveHostBindingRequest removeHostBindingRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = INT32_200,
        .extraInfo = { 1, 2, 3 } };
    EncodeRemoveHostBindingRequest(removeHostBindingRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(removeHostBindingRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, removeHostBindingRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetHostBindingManager(), RemoveHostBinding(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionRemoveHostBindingHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), RemoveHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));

    handler_ = std::make_unique<CompanionRemoveHostBindingHandler>();

    Attributes request;
    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionRemoveHostBindingHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetHostBindingManager(), RemoveHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));

    handler_ = std::make_unique<CompanionRemoveHostBindingHandler>();

    Attributes request;
    RemoveHostBindingRequest removeHostBindingRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = INT32_200,
        .extraInfo = { 1, 2, 3 } };
    EncodeRemoveHostBindingRequest(removeHostBindingRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(removeHostBindingRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, removeHostBindingRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetHostBindingManager(), RemoveHostBinding(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
