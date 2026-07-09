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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"

#include "error_guard.h"
#include "host_request_resync_handler.h"
#include "resync_device_status_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_200 = 200;

class HostRequestResyncHandlerTest : public Test {
public:
    void CreateDefaultHandler()
    {
        handler_ = std::make_unique<HostRequestResyncHandler>();
    }

protected:
    std::unique_ptr<HostRequestResyncHandler> handler_;

    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = INT32_200 };
};

HWTEST_F(HostRequestResyncHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultHandler();
    Attributes request;
    RequestDeviceResyncRequest resyncRequest = { .companionDeviceKey = companionDeviceKey_ };
    EncodeRequestDeviceResyncRequest(resyncRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(resyncRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, resyncRequest.companionDeviceKey.deviceId);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), TriggerDeviceSync(_)).Times(1);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(HostRequestResyncHandlerTest, HandleRequest_002, TestSize.Level0)
{
    // Empty request -> decode fails -> GENERAL_ERROR, no resync triggered.
    MockGuard guard;
    CreateDefaultHandler();
    Attributes request;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), TriggerDeviceSync(_)).Times(0);

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
