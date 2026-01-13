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

#include "companion_revoke_token_request.h"
#include "relative_timer.h"
#include "revoke_token_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionRevokeTokenRequestTest : public Test {
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
        request_ = std::make_shared<CompanionRevokeTokenRequest>(companionUserId_, hostDeviceKey_);
    }

protected:
    std::shared_ptr<CompanionRevokeTokenRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockMiscManager> mockMiscManager_;

    int32_t companionUserId_ = 200;
    DeviceKey hostDeviceKey_ = { .deviceId = "host_device_id", .deviceUserId = 100 };
};

HWTEST_F(CompanionRevokeTokenRequestTest, OnConnected_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(CompanionRevokeTokenRequestTest, SendRevokeTokenRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->peerDeviceKey_ = std::nullopt;
    request_->SendRevokeTokenRequest();
}

HWTEST_F(CompanionRevokeTokenRequestTest, SendRevokeTokenRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->SendRevokeTokenRequest();
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_001, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes message;
    RevokeTokenReply reply = { .result = ResultCode::SUCCESS };
    EncodeRevokeTokenReply(reply, message);

    request_->HandleRevokeTokenReply(message);
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_002, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes message;
    request_->HandleRevokeTokenReply(message);
}

HWTEST_F(CompanionRevokeTokenRequestTest, HandleRevokeTokenReply_003, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes message;
    RevokeTokenReply reply = { .result = ResultCode::GENERAL_ERROR };
    EncodeRevokeTokenReply(reply, message);

    request_->HandleRevokeTokenReply(message);
}

HWTEST_F(CompanionRevokeTokenRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(CompanionRevokeTokenRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_REVOKE_TOKEN_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(CompanionRevokeTokenRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
