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

#include "host_remove_host_binding_request.h"
#include "relative_timer.h"
#include "remove_host_binding_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class HostRemoveHostBindingRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        UserId hostUserId = 100;
        TemplateId templateId = 1;
        DeviceKey companionDeviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
            .deviceId = "companion_device_id",
            .deviceUserId = 200 };
        request_ = std::make_shared<HostRemoveHostBindingRequest>(hostUserId, templateId, companionDeviceKey);
    }

protected:
    std::shared_ptr<HostRemoveHostBindingRequest> request_;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
};

HWTEST_F(HostRemoveHostBindingRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostRemoveHostBindingRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostRemoveHostBindingRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostRemoveHostBindingRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->SetPeerDeviceKey(hostDeviceKey_);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(HostRemoveHostBindingRequestTest, SendRemoveHostBindingRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->SendRemoveHostBindingRequest();
}

HWTEST_F(HostRemoveHostBindingRequestTest, SendRemoveHostBindingRequest_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->SetPeerDeviceKey(hostDeviceKey_);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
        .Times(AtMost(1)).WillOnce(Return(false));

    request_->SendRemoveHostBindingRequest();
}

HWTEST_F(HostRemoveHostBindingRequestTest, HandleRemoveHostBindingReply_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    Attributes message;
    RemoveHostBindingReply reply = { .result = ResultCode::SUCCESS };
    EncodeRemoveHostBindingReply(reply, message);

    request_->HandleRemoveHostBindingReply(message);
}

HWTEST_F(HostRemoveHostBindingRequestTest, HandleRemoveHostBindingReply_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    Attributes message;
    request_->HandleRemoveHostBindingReply(message);
}

HWTEST_F(HostRemoveHostBindingRequestTest, HandleRemoveHostBindingReply_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    Attributes message;
    RemoveHostBindingReply reply = { .result = ResultCode::GENERAL_ERROR };
    EncodeRemoveHostBindingReply(reply, message);

    request_->HandleRemoveHostBindingReply(message);
}

HWTEST_F(HostRemoveHostBindingRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(HostRemoveHostBindingRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_REMOVE_HOST_BINDING_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostRemoveHostBindingRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
