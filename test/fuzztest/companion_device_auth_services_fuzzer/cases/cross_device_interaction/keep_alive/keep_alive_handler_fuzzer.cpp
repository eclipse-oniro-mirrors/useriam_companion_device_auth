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
#include "keep_alive_handler.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using KeepAliveHandlerFuzzFunction = void (*)(std::shared_ptr<KeepAliveHandler> &handler, FuzzedDataProvider &fuzzData);

static void FuzzHandleRequest(std::shared_ptr<KeepAliveHandler> &handler, FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData);
    Attributes reply;
    handler->HandleRequest(request, reply);
}

static void FuzzHandleRequestWithEmptyAttrs(std::shared_ptr<KeepAliveHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    Attributes emptyRequest;
    Attributes reply;
    handler->HandleRequest(emptyRequest, reply);
}

static void FuzzHandleRequestWithLargeAttrs(std::shared_ptr<KeepAliveHandler> &handler, FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData, FUZZ_MAX_ATTRIBUTES_COUNT);
    Attributes reply;
    handler->HandleRequest(request, reply);
}

static void FuzzGetMessageType(std::shared_ptr<KeepAliveHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)handler->GetMessageType();
}

static void FuzzHandleIncomingMessage(std::shared_ptr<KeepAliveHandler> &handler, FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData);
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleIncomingMessage(request, onMessageReply);
}

static void FuzzHandleIncomingMessageWithEmptyAttrs(std::shared_ptr<KeepAliveHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    Attributes emptyRequest;
    OnMessageReply onMessageReply = [](const Attributes &reply) { (void)reply; };
    handler->HandleIncomingMessage(emptyRequest, onMessageReply);
}

static void FuzzMultipleHandleRequests(std::shared_ptr<KeepAliveHandler> &handler, FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t i = 0; i < count; ++i) {
        Attributes request = GenerateFuzzAttributes(fuzzData);
        Attributes reply;
        handler->HandleRequest(request, reply);
    }
}

static void FuzzRegister(std::shared_ptr<KeepAliveHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    handler->Register();
}

static const KeepAliveHandlerFuzzFunction g_fuzzFuncs[] = {
    FuzzHandleRequest,
    FuzzHandleRequestWithEmptyAttrs,
    FuzzHandleRequestWithLargeAttrs,
    FuzzGetMessageType,
    FuzzHandleIncomingMessage,
    FuzzHandleIncomingMessageWithEmptyAttrs,
    FuzzMultipleHandleRequests,
    FuzzRegister,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(KeepAliveHandlerFuzzFunction);

void FuzzKeepAliveHandler(FuzzedDataProvider &fuzzData)
{
    auto handler = std::make_shared<KeepAliveHandler>();
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

FUZZ_REGISTER(KeepAliveHandler)

} // namespace UserIam
} // namespace OHOS
