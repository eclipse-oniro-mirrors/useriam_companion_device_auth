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

#include "companion_start_delegate_auth_handler.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData);

static void FuzzGetMessageType(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto type = handler->GetMessageType();
    (void)type;
}

static void FuzzRegister(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    handler->Register();
}

static void FuzzHandleIncomingMessage(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData);
    auto replyCallback = [](const Attributes &reply) { (void)reply; };
    OnMessageReply reply = replyCallback;
    handler->HandleIncomingMessage(request, reply);
}

static void FuzzHandleRequest(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler, FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData);
    Attributes reply;
    handler->HandleRequest(request, reply);
}

static void FuzzHandleRequestWithEmptyAttrs(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    Attributes emptyRequest;
    Attributes reply;
    handler->HandleRequest(emptyRequest, reply);
}

static void FuzzHandleRequestWithLargeAttrs(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData, FUZZ_MAX_ATTRIBUTES_COUNT);
    Attributes reply;
    handler->HandleRequest(request, reply);
}

static void FuzzMultipleHandleRequests(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t i = 0; i < count; ++i) {
        Attributes request = GenerateFuzzAttributes(fuzzData);
        Attributes reply;
        handler->HandleRequest(request, reply);
    }
}

static void FuzzCreateNewHandler(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto newHandler = std::make_shared<CompanionStartDelegateAuthHandler>();
    (void)newHandler;
    (void)handler;
}

static void FuzzGetMessageTypeMultiple(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t i = 0; i < count; ++i) {
        auto type = handler->GetMessageType();
        (void)type;
    }
}

static void FuzzHandleIncomingMessageWithNullCallback(std::shared_ptr<CompanionStartDelegateAuthHandler> &handler,
    FuzzedDataProvider &fuzzData)
{
    Attributes request = GenerateFuzzAttributes(fuzzData);
    OnMessageReply nullReply = nullptr;
    handler->HandleIncomingMessage(request, nullReply);
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzGetMessageType,
    FuzzRegister,
    FuzzHandleIncomingMessage,
    FuzzHandleRequest,
    FuzzHandleRequestWithEmptyAttrs,
    FuzzHandleRequestWithLargeAttrs,
    FuzzMultipleHandleRequests,
    FuzzCreateNewHandler,
    FuzzGetMessageTypeMultiple,
    FuzzHandleIncomingMessageWithNullCallback,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzCompanionStartDelegateAuthHandler(FuzzedDataProvider &fuzzData)
{
    auto handler = std::make_shared<CompanionStartDelegateAuthHandler>();
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
} // namespace UserIam
} // namespace OHOS
