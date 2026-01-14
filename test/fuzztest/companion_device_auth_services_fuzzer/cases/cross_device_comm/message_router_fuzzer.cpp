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
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "channel_manager.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "message_router.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const uint32_t TEST_VAL64 = 64;
}

using MessageRouterFuzzFunction = void (*)(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData);

static void FuzzSubscribeIncomingConnection(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    uint8_t msgTypeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 50);
    MessageType msgType = static_cast<MessageType>(msgTypeValue);
    auto callback = [](const Attributes &msg, OnMessageReply &onMessageReply) {
        (void)msg;
        (void)onMessageReply;
    };
    auto subscription = router->SubscribeIncomingConnection(msgType, std::move(callback));
    (void)subscription;
}

static void FuzzSubscribeMessage(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    uint8_t msgTypeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 50);
    MessageType msgType = static_cast<MessageType>(msgTypeValue);
    auto callback = [](const Attributes &msg, OnMessageReply &onMessageReply) {
        (void)msg;
        (void)onMessageReply;
    };
    auto subscription = router->SubscribeMessage(connectionName, msgType, std::move(callback));
    (void)subscription;
}

static void FuzzSendMessage(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    uint8_t msgTypeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 50);
    MessageType msgType = static_cast<MessageType>(msgTypeValue);
    Attributes request = GenerateFuzzAttributes(fuzzData);
    auto callback = [](const Attributes &reply) { (void)reply; };
    bool result = router->SendMessage(connectionName, msgType, request, std::move(callback));
    (void)result;
}

static void FuzzHandleRawMessage(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    uint32_t msgSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    auto rawMsg = fuzzData.ConsumeBytes<uint8_t>(msgSize);
    router->HandleRawMessage(connectionName, rawMsg);
}

static void FuzzHandleConnectionDown(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    router->HandleConnectionDown(connectionName);
}

static void FuzzFindMessageSubscriber(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    uint8_t msgTypeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 50);
    MessageType msgType = static_cast<MessageType>(msgTypeValue);
    auto subscriber = router->FindMessageSubscriber(connectionName, msgType);
    (void)subscriber;
}

static void FuzzHandleMessageTimeout(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    uint32_t messageSeq = fuzzData.ConsumeIntegral<uint32_t>();
    router->HandleMessageTimeout(messageSeq);
}

static void FuzzHandleTimeoutCheck(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    router->HandleTimeoutCheck();
}

static void FuzzRefreshTimeOutSubscription(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    router->RefreshTimeOutSubscription();
}

static void FuzzRefreshConnectionStatusSubscription(std::shared_ptr<MessageRouter> &router,
    FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    router->RefreshConnectionStatusSubscription(connectionName);
}

static void FuzzHandleRequest(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    MessageRouter::MessageHeader header;
    header.connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    header.messageSeq = fuzzData.ConsumeIntegral<uint32_t>();
    header.isReply = fuzzData.ConsumeBool();
    header.msgType = static_cast<MessageType>(fuzzData.ConsumeIntegral<uint8_t>());
    Attributes payload = GenerateFuzzAttributes(fuzzData);
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    router->HandleRequest(header, payload, channelId);
}

static void FuzzHandleReply(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    MessageRouter::MessageHeader header;
    header.connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    header.messageSeq = fuzzData.ConsumeIntegral<uint32_t>();
    header.isReply = fuzzData.ConsumeBool();
    header.msgType = static_cast<MessageType>(fuzzData.ConsumeIntegral<uint8_t>());
    Attributes payload = GenerateFuzzAttributes(fuzzData);
    router->HandleReply(header, payload);
}

static void FuzzSendErrorReply(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    MessageRouter::MessageHeader requestHeader;
    requestHeader.connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    requestHeader.messageSeq = fuzzData.ConsumeIntegral<uint32_t>();
    requestHeader.isReply = fuzzData.ConsumeBool();
    requestHeader.msgType = static_cast<MessageType>(fuzzData.ConsumeIntegral<uint8_t>());
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    router->SendErrorReply(requestHeader, channelId);
}

static void FuzzSendReply(std::shared_ptr<MessageRouter> &router, FuzzedDataProvider &fuzzData)
{
    MessageRouter::MessageHeader requestHeader;
    requestHeader.connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    requestHeader.messageSeq = fuzzData.ConsumeIntegral<uint32_t>();
    requestHeader.isReply = fuzzData.ConsumeBool();
    requestHeader.msgType = static_cast<MessageType>(fuzzData.ConsumeIntegral<uint8_t>());
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    Attributes reply = GenerateFuzzAttributes(fuzzData);
    router->SendReply(requestHeader, channelId, reply);
}

static const MessageRouterFuzzFunction g_fuzzFuncs[] = {
    FuzzSubscribeIncomingConnection,
    FuzzSubscribeMessage,
    FuzzSendMessage,
    FuzzHandleRawMessage,
    FuzzHandleConnectionDown,
    FuzzFindMessageSubscriber,
    FuzzHandleMessageTimeout,
    FuzzHandleTimeoutCheck,
    FuzzRefreshTimeOutSubscription,
    FuzzRefreshConnectionStatusSubscription,
    FuzzHandleRequest,
    FuzzHandleReply,
    FuzzSendErrorReply,
    FuzzSendReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(MessageRouterFuzzFunction);

void FuzzMessageRouter(FuzzedDataProvider &fuzzData)
{
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    auto channelMgr = std::make_shared<ChannelManager>(channels);
    if (!channelMgr) {
        return;
    }

    auto connectionMgr = std::make_shared<ConnectionManager>(channelMgr, nullptr);
    if (!connectionMgr) {
        return;
    }

    auto router = MessageRouter::Create(connectionMgr, channelMgr);
    if (!router) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](router, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(MessageRouter)

} // namespace UserIam
} // namespace OHOS
