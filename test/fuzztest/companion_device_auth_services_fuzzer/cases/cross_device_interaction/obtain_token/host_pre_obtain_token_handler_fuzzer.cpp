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

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "host_pre_obtain_token_handler.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HostPreObtainTokenHandlerFuzzFunction = void (*)(std::shared_ptr<HostPreObtainTokenHandler> &handler,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMessageType(std::shared_ptr<HostPreObtainTokenHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)handler->GetMessageType();
}

static void FuzzRegister(std::shared_ptr<HostPreObtainTokenHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    handler->Register();
}

static void FuzzHandleIncomingMessage(std::shared_ptr<HostPreObtainTokenHandler> &handler, FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData, FUZZ_MAX_ATTRIBUTES_COUNT);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleIncomingMessage(request, onMessageReply);
}

static void FuzzHandleRequest(std::shared_ptr<HostPreObtainTokenHandler> &handler, FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData, FUZZ_MAX_ATTRIBUTES_COUNT);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleRequest(request, onMessageReply);
}

static void FuzzHandleRequestWithEmptyAttrs(std::shared_ptr<HostPreObtainTokenHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    Attributes emptyRequest;
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleRequest(emptyRequest, onMessageReply);
}

static void FuzzHandleRequestWithLargeAttrs(std::shared_ptr<HostPreObtainTokenHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData, 100);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleRequest(request, onMessageReply);
}

static void FuzzMultipleHandleRequests(std::shared_ptr<HostPreObtainTokenHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    uint32_t count = fuzzData.ConsumeIntegralInRange<uint32_t>(1, 5);
    for (uint32_t i = 0; i < count; ++i) {
        Attributes request = GenerateFuzzAttributes(fuzzData, FUZZ_MAX_ATTRIBUTES_COUNT);
        handler->HandleRequest(request, onMessageReply);
    }
}

static void FuzzCreateNewHandler(std::shared_ptr<HostPreObtainTokenHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto newHandler = std::make_shared<HostPreObtainTokenHandler>();
    if (!newHandler) {
        return;
    }
    (void)newHandler->GetMessageType();
    (void)handler; // Keep original handler unchanged
}

static void FuzzGetMessageTypeMultiple(std::shared_ptr<HostPreObtainTokenHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    uint32_t count = fuzzData.ConsumeIntegralInRange<uint32_t>(1, 10);
    for (uint32_t i = 0; i < count; ++i) {
        (void)handler->GetMessageType();
    }
}

static void FuzzHandleIncomingMessageWithNullCallback(std::shared_ptr<HostPreObtainTokenHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData, FUZZ_MAX_ATTRIBUTES_COUNT);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleIncomingMessage(request, onMessageReply);
}

static const HostPreObtainTokenHandlerFuzzFunction g_fuzzFuncs[] = { FuzzGetMessageType, FuzzRegister,
    FuzzHandleIncomingMessage, FuzzHandleRequest, FuzzHandleRequestWithEmptyAttrs, FuzzHandleRequestWithLargeAttrs,
    FuzzMultipleHandleRequests, FuzzCreateNewHandler, FuzzGetMessageTypeMultiple,
    FuzzHandleIncomingMessageWithNullCallback };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostPreObtainTokenHandlerFuzzFunction);

void FuzzHostPreObtainTokenHandler(FuzzedDataProvider &fuzzData)
{
    auto handler = std::make_shared<HostPreObtainTokenHandler>();
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

FUZZ_REGISTER(FuzzHostPreObtainTokenHandler)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
