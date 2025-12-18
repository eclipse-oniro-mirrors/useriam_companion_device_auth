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

#include "companion_token_auth_handler.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_security_agent.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "token_auth_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionTokenAuthHandlerTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto hostBindingMgr =
            std::shared_ptr<IHostBindingManager>(&mockHostBindingManager_, [](IHostBindingManager *) {});
        SingletonManager::GetInstance().SetHostBindingManager(hostBindingMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        ON_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
            .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
        ON_CALL(mockSecurityAgent_, CompanionProcessTokenAuth(_, _)).WillByDefault(Return(ResultCode::SUCCESS));

        handler_ = std::make_unique<CompanionTokenAuthHandler>();
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    std::unique_ptr<CompanionTokenAuthHandler> handler_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;

    int32_t companionUserId_ = 200;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    std::vector<uint8_t> extraInfo_ = { 1, 2, 3, 4 };
    HostBindingStatus hostBindingStatus_;
};

HWTEST_F(CompanionTokenAuthHandlerTest, HandleRequest_001, TestSize.Level0)
{
    Attributes request;
    TokenAuthRequest tokenAuthRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    EncodeTokenAuthRequest(tokenAuthRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(tokenAuthRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, tokenAuthRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionProcessTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = -1;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionTokenAuthHandlerTest, HandleRequest_002, TestSize.Level0)
{
    Attributes request;
    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = -1;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionTokenAuthHandlerTest, HandleRequest_003, TestSize.Level0)
{
    Attributes request;
    TokenAuthRequest tokenAuthRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    EncodeTokenAuthRequest(tokenAuthRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(tokenAuthRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, tokenAuthRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = -1;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionTokenAuthHandlerTest, HandleRequest_004, TestSize.Level0)
{
    Attributes request;
    TokenAuthRequest tokenAuthRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    EncodeTokenAuthRequest(tokenAuthRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(tokenAuthRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, tokenAuthRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionProcessTokenAuth(_, _)).WillOnce(Return(ResultCode::FAIL));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = -1;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::FAIL));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
