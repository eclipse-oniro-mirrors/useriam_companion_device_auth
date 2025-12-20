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
#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "relative_timer.h"
#include "remove_host_binding_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

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
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        ON_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(hostDeviceKey_)));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
    }

    void TearDown() override
    {
        request_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

    void CreateDefaultRequest()
    {
        UserId hostUserId = 100;
        DeviceKey companionDeviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
            .deviceId = "companion_device_id",
            .deviceUserId = 200 };
        request_ = std::make_shared<HostRemoveHostBindingRequest>(hostUserId, companionDeviceKey);
    }

protected:
    std::shared_ptr<HostRemoveHostBindingRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockMiscManager> mockMiscManager_;

    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
};

HWTEST_F(HostRemoveHostBindingRequestTest, OnStart_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostRemoveHostBindingRequestTest, OnStart_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostRemoveHostBindingRequestTest, OnStart_003, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostRemoveHostBindingRequestTest, OnConnected_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->SetPeerDeviceKey(hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(HostRemoveHostBindingRequestTest, SendRemoveHostBindingRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->SendRemoveHostBindingRequest();
}

HWTEST_F(HostRemoveHostBindingRequestTest, SendRemoveHostBindingRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->SetPeerDeviceKey(hostDeviceKey_);

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(nullopt));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->SendRemoveHostBindingRequest();
}

HWTEST_F(HostRemoveHostBindingRequestTest, HandleRemoveHostBindingReply_001, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes message;
    RemoveHostBindingReply reply = { .result = ResultCode::SUCCESS };
    EncodeRemoveHostBindingReply(reply, message);

    request_->HandleRemoveHostBindingReply(message);
}

HWTEST_F(HostRemoveHostBindingRequestTest, HandleRemoveHostBindingReply_002, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes message;
    request_->HandleRemoveHostBindingReply(message);
}

HWTEST_F(HostRemoveHostBindingRequestTest, HandleRemoveHostBindingReply_003, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes message;
    RemoveHostBindingReply reply = { .result = ResultCode::GENERAL_ERROR };
    EncodeRemoveHostBindingReply(reply, message);

    request_->HandleRemoveHostBindingReply(message);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
