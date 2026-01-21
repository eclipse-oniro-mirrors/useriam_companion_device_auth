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

#include "common_message.h"
#include "companion_issue_token_request.h"
#include "companion_pre_issue_token_handler.h"
#include "issue_token_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_time_keeper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionPreIssueTokenHandlerTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestFactory = std::shared_ptr<IRequestFactory>(&mockRequestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto hostBindingMgr =
            std::shared_ptr<IHostBindingManager>(&mockHostBindingManager_, [](IHostBindingManager *) {});
        SingletonManager::GetInstance().SetHostBindingManager(hostBindingMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        ON_CALL(mockRequestFactory_, CreateCompanionIssueTokenRequest(_, _, _, _))
            .WillByDefault(Invoke([this](const std::string &connectionName, const Attributes &request,
                                      OnMessageReply replyCallback, const DeviceKey &) {
                auto result = DecodePreIssueTokenRequest(request);
                PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
                return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                    preRequest.hostDeviceKey);
            }));
        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));

        handler_ = std::make_unique<CompanionPreIssueTokenHandler>();
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    std::unique_ptr<CompanionPreIssueTokenHandler> handler_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;
};

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_001, TestSize.Level0)
{
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    DeviceKey hostDeviceKey = {};
    EncodeHostDeviceKey(hostDeviceKey, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 100);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &) { replyCalled = true; };

    EXPECT_CALL(mockRequestFactory_, CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &connectionName, const Attributes &request,
                             OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true));

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_FALSE(replyCalled);
}

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_002, TestSize.Level0)
{
    Attributes request;

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_003, TestSize.Level0)
{
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_004, TestSize.Level0)
{
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    DeviceKey hostDeviceKey = {};
    EncodeHostDeviceKey(hostDeviceKey, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 100);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    EXPECT_CALL(mockRequestFactory_, CreateCompanionIssueTokenRequest(_, _, _, _)).WillOnce(Return(nullptr));

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_005, TestSize.Level0)
{
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    DeviceKey hostDeviceKey = {};
    EncodeHostDeviceKey(hostDeviceKey, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 100);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    EXPECT_CALL(mockRequestFactory_, CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &connectionName, const Attributes &request,
                             OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
