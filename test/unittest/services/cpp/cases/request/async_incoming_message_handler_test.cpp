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

#include "async_incoming_message_handler.h"
#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_time_keeper.h"

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

class MockAsyncIncomingMessageHandler : public AsyncIncomingMessageHandler {
public:
    explicit MockAsyncIncomingMessageHandler(MessageType messageType) : AsyncIncomingMessageHandler(messageType)
    {
    }

    MOCK_METHOD(void, HandleRequest, (const Attributes &request, OnMessageReply &onMessageReply), (override));
};

class AsyncIncomingMessageHandlerTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        ON_CALL(mockCrossDeviceCommManager_, SubscribeIncomingConnection(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
};

HWTEST_F(AsyncIncomingMessageHandlerTest, Register_001, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockAsyncIncomingMessageHandler>>(MessageType::TOKEN_AUTH);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeIncomingConnection(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    handler->Register();
}

HWTEST_F(AsyncIncomingMessageHandlerTest, Register_002, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockAsyncIncomingMessageHandler>>(MessageType::TOKEN_AUTH);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeIncomingConnection(_, _)).WillOnce(Return(ByMove(nullptr)));

    handler->Register();
}

HWTEST_F(AsyncIncomingMessageHandlerTest, Register_003, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockAsyncIncomingMessageHandler>>(MessageType::TOKEN_AUTH);

    handler->Register();
    handler->Register();
}

HWTEST_F(AsyncIncomingMessageHandlerTest, HandleIncomingMessage_001, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockAsyncIncomingMessageHandler>>(MessageType::TOKEN_AUTH);

    Attributes request;
    OnMessageReply onMessageReply = [](const Attributes &) {};

    EXPECT_CALL(*handler, HandleRequest(_, _)).Times(1);

    handler->HandleIncomingMessage(request, onMessageReply);
}

HWTEST_F(AsyncIncomingMessageHandlerTest, HandleIncomingMessage_002, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockAsyncIncomingMessageHandler>>(MessageType::TOKEN_AUTH);

    Attributes request;
    OnMessageReply onMessageReply = nullptr;

    EXPECT_CALL(*handler, HandleRequest(_, _)).Times(0);

    handler->HandleIncomingMessage(request, onMessageReply);
}

HWTEST_F(AsyncIncomingMessageHandlerTest, GetMessageType_001, TestSize.Level0)
{
    auto handler = std::make_shared<NiceMock<MockAsyncIncomingMessageHandler>>(MessageType::TOKEN_AUTH);

    MessageType type = handler->GetMessageType();
    EXPECT_EQ(MessageType::TOKEN_AUTH, type);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
