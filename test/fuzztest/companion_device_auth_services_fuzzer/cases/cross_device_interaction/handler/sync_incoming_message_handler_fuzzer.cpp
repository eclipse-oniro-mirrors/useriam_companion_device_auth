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

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "host_revoke_token_handler.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr int32_t INT32_5 = 5;

using SyncIncomingMessageHandlerFuzzFunction = void (*)(std::shared_ptr<HostRevokeTokenHandler> &handler,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMessageType(std::shared_ptr<HostRevokeTokenHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)handler->GetMessageType();
}

static void FuzzRegister(std::shared_ptr<HostRevokeTokenHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    handler->Register();
}

static void FuzzHandleIncomingMessage(std::shared_ptr<HostRevokeTokenHandler> &handler, FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleIncomingMessage(request, onMessageReply);
}

static void FuzzHandleIncomingMessageWithEmptyAttrs(std::shared_ptr<HostRevokeTokenHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    Attributes emptyRequest;
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleIncomingMessage(emptyRequest, onMessageReply);
}

static void FuzzHandleIncomingMessageWithLargeAttrs(std::shared_ptr<HostRevokeTokenHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData, FUZZ_MAX_ATTRIBUTES_COUNT);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleIncomingMessage(request, onMessageReply);
}

static void FuzzMultipleHandleIncomingMessages(std::shared_ptr<HostRevokeTokenHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t i = 0; i < count; ++i) {
        Attributes request = GenerateFuzzAttributes(fuzzData);
        OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
        handler->HandleIncomingMessage(request, onMessageReply);
    }
}

static const SyncIncomingMessageHandlerFuzzFunction g_fuzzFuncs[] = {
    FuzzGetMessageType,
    FuzzRegister,
    FuzzHandleIncomingMessage,
    FuzzHandleIncomingMessageWithEmptyAttrs,
    FuzzHandleIncomingMessageWithLargeAttrs,
    FuzzMultipleHandleIncomingMessages,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SyncIncomingMessageHandlerFuzzFunction);

void FuzzSyncIncomingMessageHandler(FuzzedDataProvider &fuzzData)
{
    auto handler = std::make_shared<HostRevokeTokenHandler>();
    if (!handler) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](handler, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](handler, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzSyncIncomingMessageHandler)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
