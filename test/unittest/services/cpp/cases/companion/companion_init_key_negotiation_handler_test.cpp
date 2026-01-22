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
#include "companion_add_companion_request.h"
#include "companion_init_key_negotiation_handler.h"
#include "relative_timer.h"
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

class CompanionInitKeyNegotiationHandlerTest : public Test {
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

        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));

        DeviceKey companionDeviceKey = { .deviceId = "companion_device_id", .deviceUserId = 200 };
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(companionDeviceKey)));
        ON_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
            .WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _))
            .WillByDefault(Invoke(
                [](const std::string &, MessageType, OnMessage &&) { return std::make_unique<Subscription>([] {}); }));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::END_ADD_HOST_BINDING, _))
            .WillByDefault(Invoke(
                [](const std::string &, MessageType, OnMessage &&) { return std::make_unique<Subscription>([] {}); }));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
            .WillByDefault(Return(ByMove(std::make_unique<Subscription>([] {}))));
        ON_CALL(mockCrossDeviceCommManager_, GetConnectionStatus(_)).WillByDefault(Return(ConnectionStatus::CONNECTED));
        ON_CALL(mockSecurityAgent_, CompanionInitKeyNegotiation(_, _))
            .WillByDefault(
                Invoke([](const CompanionInitKeyNegotiationInput &, CompanionInitKeyNegotiationOutput &output) {
                    output.initKeyNegotiationReply = { 5, 6, 7, 8 };
                    return ResultCode::SUCCESS;
                }));
        ON_CALL(mockHostBindingManager_, EndAddHostBinding(_, _, _)).WillByDefault(Return(ResultCode::SUCCESS));

        handler_ = std::make_unique<CompanionInitKeyNegotiationHandler>();
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    std::unique_ptr<CompanionInitKeyNegotiationHandler> handler_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;
};

HWTEST_F(CompanionInitKeyNegotiationHandlerTest, HandleRequest_001, TestSize.Level0)
{
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    // Manually set all required DeviceKey attributes
    DeviceKey hostDeviceKey = {};
    hostDeviceKey.deviceUserId = 100;
    hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    hostDeviceKey.deviceId = "test_host_device";
    request.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey.deviceUserId);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey.deviceId);
    // Set extraInfo for InitKeyNegotiationRequest
    request.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, { 1, 2, 3, 4 });

    std::shared_ptr<IRequest> capturedRequest;
    ON_CALL(mockRequestFactory_, CreateCompanionAddCompanionRequest(_, _, _, _))
        .WillByDefault(Invoke([this, &capturedRequest](const std::string &connectionName, const Attributes &request,
                                  OnMessageReply firstReply, const DeviceKey &deviceKey) {
            auto req = std::make_shared<CompanionAddCompanionRequest>(connectionName, request, std::move(firstReply),
                deviceKey);
            capturedRequest = req;
            return req;
        }));

    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Invoke([](const std::shared_ptr<IRequest> &request) -> bool {
        request->Start();
        return true;
    }));

    int replyCallCount = 0;
    int32_t lastResult = -1;
    OnMessageReply onMessageReply = [&replyCallCount, &lastResult](const Attributes &reply) {
        ++replyCallCount;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        lastResult = result;
    };

    handler_->HandleRequest(request, onMessageReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(replyCallCount, 1);
    EXPECT_EQ(lastResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionInitKeyNegotiationHandlerTest, HandleRequest_002, TestSize.Level0)
{
    Attributes request;

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionInitKeyNegotiationHandlerTest, HandleRequest_003, TestSize.Level0)
{
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    // Manually set all required DeviceKey attributes
    DeviceKey hostDeviceKey = {};
    hostDeviceKey.deviceUserId = 100;
    hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    hostDeviceKey.deviceId = "test_host_device";
    request.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey.deviceUserId);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey.deviceId);

    EXPECT_CALL(mockRequestFactory_, CreateCompanionAddCompanionRequest(_, _, _, _)).WillOnce(Return(nullptr));

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionInitKeyNegotiationHandlerTest, HandleRequest_004, TestSize.Level0)
{
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    // Manually set all required DeviceKey attributes
    DeviceKey hostDeviceKey = {};
    hostDeviceKey.deviceUserId = 100;
    hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    hostDeviceKey.deviceId = "test_host_device";
    request.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostDeviceKey.deviceUserId);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey.deviceId);

    EXPECT_CALL(mockRequestFactory_, CreateCompanionAddCompanionRequest(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &connectionName, const Attributes &request, OnMessageReply firstReply,
                             const DeviceKey &deviceKey) {
            return std::make_shared<CompanionAddCompanionRequest>(connectionName, request, std::move(firstReply),
                deviceKey);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS