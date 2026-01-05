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

#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "sync_incoming_message_handler.h"
#include "task_runner_manager.h"

#include "mock_cross_device_comm_manager.h"

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

class MockSyncIncomingMessageHandler : public SyncIncomingMessageHandler {
public:
    explicit MockSyncIncomingMessageHandler(MessageType messageType) : SyncIncomingMessageHandler(messageType)
    {
    }

    MOCK_METHOD(void, HandleRequest, (const Attributes &request, Attributes &reply), (override));
};

class SyncIncomingMessageHandlerTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        ON_CALL(mockCrossDeviceCommManager_, SubscribeIncomingConnection(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
};

HWTEST_F(SyncIncomingMessageHandlerTest, Register_001, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockSyncIncomingMessageHandler>>(MessageType::SYNC_DEVICE_STATUS);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeIncomingConnection(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    handler->Register();
}

HWTEST_F(SyncIncomingMessageHandlerTest, Register_002, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockSyncIncomingMessageHandler>>(MessageType::SYNC_DEVICE_STATUS);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeIncomingConnection(_, _)).WillOnce(Return(ByMove(nullptr)));

    handler->Register();
}

HWTEST_F(SyncIncomingMessageHandlerTest, Register_003, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockSyncIncomingMessageHandler>>(MessageType::SYNC_DEVICE_STATUS);

    handler->Register();
    handler->Register();
}

HWTEST_F(SyncIncomingMessageHandlerTest, HandleIncomingMessage_001, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockSyncIncomingMessageHandler>>(MessageType::SYNC_DEVICE_STATUS);

    Attributes request;
    bool callbackInvoked = false;
    OnMessageReply onMessageReply = [&callbackInvoked](const Attributes &reply) {
        callbackInvoked = true;
        int32_t result = 0;
        bool hasResult = reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        EXPECT_TRUE(hasResult);
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    EXPECT_CALL(*handler, HandleRequest(_, _)).WillOnce(Return());

    handler->HandleIncomingMessage(request, onMessageReply);
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SyncIncomingMessageHandlerTest, HandleIncomingMessage_002, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockSyncIncomingMessageHandler>>(MessageType::SYNC_DEVICE_STATUS);

    Attributes request;
    OnMessageReply onMessageReply = nullptr;

    EXPECT_CALL(*handler, HandleRequest(_, _)).Times(0);

    handler->HandleIncomingMessage(request, onMessageReply);
}

HWTEST_F(SyncIncomingMessageHandlerTest, HandleIncomingMessage_003, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockSyncIncomingMessageHandler>>(MessageType::SYNC_DEVICE_STATUS);

    Attributes request;

    bool callbackInvoked = false;
    OnMessageReply onMessageReply = [&callbackInvoked](const Attributes &reply) {
        callbackInvoked = true;
        int32_t result = 0;
        bool hasResult = reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result);
        EXPECT_TRUE(hasResult);
        EXPECT_EQ(static_cast<int32_t>(ResultCode::SUCCESS), result);
    };

    EXPECT_CALL(*handler, HandleRequest(_, _)).WillOnce(Invoke([](const Attributes &request, Attributes &reply) {
        reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::SUCCESS));
    }));

    handler->HandleIncomingMessage(request, onMessageReply);
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SyncIncomingMessageHandlerTest, GetMessageType_001, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockSyncIncomingMessageHandler>>(MessageType::SYNC_DEVICE_STATUS);

    MessageType type = handler->GetMessageType();
    EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, type);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
