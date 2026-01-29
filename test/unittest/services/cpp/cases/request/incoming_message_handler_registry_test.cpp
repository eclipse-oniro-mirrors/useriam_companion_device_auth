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

#include "incoming_message_handler.h"
#include "incoming_message_handler_registry.h"
#include "mock_guard.h"
#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class MockIncomingMessageHandler : public IncomingMessageHandler {
public:
    MOCK_METHOD(void, Register, (), (override));
    MOCK_METHOD(void, HandleIncomingMessage, (const Attributes &request, OnMessageReply &onMessageReply), (override));
    MOCK_METHOD(MessageType, GetMessageType, (), (const, override));
};

class IncomingMessageHandlerRegistryTest : public Test {
public:
};

HWTEST_F(IncomingMessageHandlerRegistryTest, Create_001, TestSize.Level0)
{
    MockGuard guard;
    auto registry = IncomingMessageHandlerRegistry::Create();
    EXPECT_NE(nullptr, registry);
}

HWTEST_F(IncomingMessageHandlerRegistryTest, AddHandler_001, TestSize.Level0)
{
    MockGuard guard;
    auto registry = IncomingMessageHandlerRegistry::Create();
    ASSERT_NE(nullptr, registry);

    auto handler = std::make_shared<NiceMock<MockIncomingMessageHandler>>();
    EXPECT_CALL(*handler, Register()).Times(0);

    registry->AddHandler(handler);
}

HWTEST_F(IncomingMessageHandlerRegistryTest, AddHandler_002, TestSize.Level0)
{
    MockGuard guard;
    auto registry = IncomingMessageHandlerRegistry::Create();
    ASSERT_NE(nullptr, registry);

    registry->AddHandler(nullptr);
}

HWTEST_F(IncomingMessageHandlerRegistryTest, AddHandler_003, TestSize.Level0)
{
    MockGuard guard;
    auto registry = IncomingMessageHandlerRegistry::Create();
    ASSERT_NE(nullptr, registry);

    registry->RegisterHandlers();

    auto handler = std::make_shared<NiceMock<MockIncomingMessageHandler>>();
    EXPECT_CALL(*handler, Register()).Times(1);

    registry->AddHandler(handler);
}

HWTEST_F(IncomingMessageHandlerRegistryTest, RegisterHandlers_001, TestSize.Level0)
{
    MockGuard guard;
    auto registry = IncomingMessageHandlerRegistry::Create();
    ASSERT_NE(nullptr, registry);

    bool result = registry->RegisterHandlers();
    EXPECT_TRUE(result);
}

HWTEST_F(IncomingMessageHandlerRegistryTest, RegisterHandlers_002, TestSize.Level0)
{
    MockGuard guard;
    auto registry = IncomingMessageHandlerRegistry::Create();
    ASSERT_NE(nullptr, registry);

    bool result1 = registry->RegisterHandlers();
    EXPECT_TRUE(result1);

    bool result2 = registry->RegisterHandlers();
    EXPECT_TRUE(result2);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
