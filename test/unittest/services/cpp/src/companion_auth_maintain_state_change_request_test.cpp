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

#include "auth_maintain_state_change_message.h"
#include "companion_auth_maintain_state_change_request.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "relative_timer.h"
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

class CompanionAuthMaintainStateChangeRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        ON_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
    }

    void TearDown() override
    {
        request_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

    void CreateDefaultRequest(bool authMaintainState)
    {
        request_ = std::make_shared<CompanionAuthMaintainStateChangeRequest>(hostDeviceKey_, authMaintainState);
    }

protected:
    std::shared_ptr<CompanionAuthMaintainStateChangeRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockMiscManager> mockMiscManager_;

    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
};

HWTEST_F(CompanionAuthMaintainStateChangeRequestTest, OnConnected_001, TestSize.Level0)
{
    CreateDefaultRequest(true);

    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(CompanionAuthMaintainStateChangeRequestTest, SendAuthMaintainStateChangeRequest_001, TestSize.Level0)
{
    CreateDefaultRequest(false);

    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->SendAuthMaintainStateChangeRequest();
}

HWTEST_F(CompanionAuthMaintainStateChangeRequestTest, HandleAuthMaintainStateChangeReply_001, TestSize.Level0)
{
    CreateDefaultRequest(true);

    AuthMaintainStateChangeReplyMsg replyMsg = { .result = ResultCode::SUCCESS };
    Attributes message;
    EncodeAuthMaintainStateChangeReply(replyMsg, message);

    request_->HandleAuthMaintainStateChangeReply(message);
}

HWTEST_F(CompanionAuthMaintainStateChangeRequestTest, HandleAuthMaintainStateChangeReply_002, TestSize.Level0)
{
    CreateDefaultRequest(true);

    Attributes badMessage;
    request_->HandleAuthMaintainStateChangeReply(badMessage);
}

HWTEST_F(CompanionAuthMaintainStateChangeRequestTest, HandleAuthMaintainStateChangeReply_003, TestSize.Level0)
{
    CreateDefaultRequest(true);

    AuthMaintainStateChangeReplyMsg replyMsg = { .result = ResultCode::GENERAL_ERROR };
    Attributes message;
    EncodeAuthMaintainStateChangeReply(replyMsg, message);

    request_->HandleAuthMaintainStateChangeReply(message);
}

HWTEST_F(CompanionAuthMaintainStateChangeRequestTest, CompleteWithError_001, TestSize.Level0)
{
    CreateDefaultRequest(true);

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionAuthMaintainStateChangeRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    CreateDefaultRequest(true);

    request_->CompleteWithSuccess();
}

HWTEST_F(CompanionAuthMaintainStateChangeRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    CreateDefaultRequest(true);

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
