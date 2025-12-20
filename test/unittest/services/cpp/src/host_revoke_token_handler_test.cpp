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

#include "error_guard.h"
#include "host_revoke_token_handler.h"
#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_security_agent.h"
#include "relative_timer.h"
#include "revoke_token_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class HostRevokeTokenHandlerTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
            .WillByDefault(Return(std::make_optional(companionStatus_)));
        ON_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

        handler_ = std::make_unique<HostRevokeTokenHandler>();
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    std::unique_ptr<HostRevokeTokenHandler> handler_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;

    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    CompanionStatus companionStatus_;
};

HWTEST_F(HostRevokeTokenHandlerTest, HandleRequest_001, TestSize.Level0)
{
    Attributes request;
    RevokeTokenRequest revokeTokenRequest = { .hostUserId = 100, .companionDeviceKey = companionDeviceKey_ };
    EncodeRevokeTokenRequest(revokeTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(revokeTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, revokeTokenRequest.companionDeviceKey.deviceId);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(HostRevokeTokenHandlerTest, HandleRequest_002, TestSize.Level0)
{
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

HWTEST_F(HostRevokeTokenHandlerTest, HandleRequest_003, TestSize.Level0)
{
    Attributes request;
    RevokeTokenRequest revokeTokenRequest = { .hostUserId = 100, .companionDeviceKey = companionDeviceKey_ };
    EncodeRevokeTokenRequest(revokeTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(revokeTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, revokeTokenRequest.companionDeviceKey.deviceId);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(nullopt));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(HostRevokeTokenHandlerTest, HandleRequest_004, TestSize.Level0)
{
    Attributes request;
    RevokeTokenRequest revokeTokenRequest = { .hostUserId = 100, .companionDeviceKey = companionDeviceKey_ };
    EncodeRevokeTokenRequest(revokeTokenRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(revokeTokenRequest.companionDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, revokeTokenRequest.companionDeviceKey.deviceId);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

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
