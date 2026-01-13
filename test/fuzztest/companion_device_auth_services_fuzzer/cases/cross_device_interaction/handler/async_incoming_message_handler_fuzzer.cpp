/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "async_incoming_message_handler.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Mock AsyncIncomingMessageHandler for testing
class MockAsyncIncomingMessageHandler : public AsyncIncomingMessageHandler {
public:
    explicit MockAsyncIncomingMessageHandler(MessageType messageType) : AsyncIncomingMessageHandler(messageType)
    {
    }

    void HandleRequest(const Attributes &request, OnMessageReply &onMessageReply) override
    {
        (void)request;
        (void)onMessageReply;
    }

    MessageType GetMessageType() const override
    {
        return messageType_;
    }
};

using AsyncIncomingMessageHandlerFuzzFunction = void (*)(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMessageType(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto type = handler->GetMessageType();
    (void)type;
}

static void FuzzRegister(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    handler->Register();
}

static void FuzzHandleIncomingMessage(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData);
    auto replyCallback = [](const Attributes &reply) { (void)reply; };
    OnMessageReply reply = replyCallback;
    handler->HandleIncomingMessage(request, reply);
}

static void FuzzConstructor(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler, FuzzedDataProvider &fuzzData)
{
    MessageType testType = static_cast<MessageType>(fuzzData.ConsumeIntegral<uint8_t>());
    auto handler2 = std::make_shared<MockAsyncIncomingMessageHandler>(testType);
    (void)handler2;
    (void)handler;
}

// Test HandleRequest with empty attributes
static void FuzzHandleRequestEmpty(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    Attributes emptyRequest;
    auto replyCallback = [](const Attributes &reply) { (void)reply; };
    OnMessageReply reply = replyCallback;
    handler->HandleRequest(emptyRequest, reply);
}

// Test HandleRequest with large attributes
static void FuzzHandleRequestLarge(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes largeRequest = GenerateFuzzAttributes(fuzzData, FUZZ_MAX_ATTRIBUTES_COUNT);
    auto replyCallback = [](const Attributes &reply) { (void)reply; };
    OnMessageReply reply = replyCallback;
    handler->HandleRequest(largeRequest, reply);
}

// Test multiple HandleIncomingMessage calls
static void FuzzHandleMultipleMessages(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    auto replyCallback = [](const Attributes &reply) { (void)reply; };
    OnMessageReply reply = replyCallback;
    int num = 5;
    for (int i = 0; i < num; ++i) {
        Attributes request = GenerateFuzzAttributes(fuzzData);
        handler->HandleIncomingMessage(request, reply);
    }
}

// Test GetMessageType multiple times
static void FuzzGetMessageTypeRepeated(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    int num = 10;
    for (int i = 0; i < num; ++i) {
        auto type = handler->GetMessageType();
        (void)type;
    }
}

// Test Register multiple times
static void FuzzRegisterRepeated(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    int num = 5;
    for (int i = 0; i < num; ++i) {
        handler->Register();
    }
}

// Test HandleIncomingMessage with nullptr callback (should be handled safely)
static void FuzzHandleWithNullCallback(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData);
    // Create a callback that does nothing
    auto nullReplyCallback = [](const Attributes &reply) { (void)reply; };
    OnMessageReply reply = nullReplyCallback;
    handler->HandleIncomingMessage(request, reply);
}

// Test combination: Register then HandleIncomingMessage
static void FuzzRegisterThenHandle(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    handler->Register();
    Attributes request = GenerateFuzzAttributes(fuzzData);
    auto replyCallback = [](const Attributes &reply) { (void)reply; };
    OnMessageReply reply = replyCallback;
    handler->HandleIncomingMessage(request, reply);
}

// Test multiple handler instances
static void FuzzMultipleHandlers(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    MessageType type1 = static_cast<MessageType>(fuzzData.ConsumeIntegral<uint8_t>());
    MessageType type2 = static_cast<MessageType>(fuzzData.ConsumeIntegral<uint8_t>());
    auto handler2 = std::make_shared<MockAsyncIncomingMessageHandler>(type1);
    auto handler3 = std::make_shared<MockAsyncIncomingMessageHandler>(type2);
    (void)handler2;
    (void)handler3;
    (void)handler;
}

// Test GetMessageType after Register
static void FuzzGetTypeAfterRegister(std::shared_ptr<MockAsyncIncomingMessageHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    handler->Register();
    auto type = handler->GetMessageType();
    (void)type;
}

static const AsyncIncomingMessageHandlerFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMessageType,
    FuzzRegister,
    FuzzHandleIncomingMessage,
    FuzzConstructor,
    FuzzHandleRequestEmpty,
    FuzzHandleRequestLarge,
    FuzzHandleMultipleMessages,
    FuzzGetMessageTypeRepeated,
    FuzzRegisterRepeated,
    FuzzHandleWithNullCallback,
    FuzzRegisterThenHandle,
    FuzzMultipleHandlers,
    FuzzGetTypeAfterRegister,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(AsyncIncomingMessageHandlerFuzzFunction);

void FuzzAsyncIncomingMessageHandler(FuzzedDataProvider &fuzzData)
{
    MessageType messageType = static_cast<MessageType>(fuzzData.ConsumeIntegral<uint8_t>());
    auto handler = std::make_shared<MockAsyncIncomingMessageHandler>(messageType);
    if (!handler) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](handler, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(AsyncIncomingMessageHandler)

} // namespace UserIam
} // namespace OHOS
