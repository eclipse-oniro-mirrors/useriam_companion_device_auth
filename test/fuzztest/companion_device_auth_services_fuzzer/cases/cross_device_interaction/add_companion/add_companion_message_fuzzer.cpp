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

#include "add_companion_message.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using AddCompanionMessageFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzEncodeInitKeyNegotiationRequest(FuzzedDataProvider &fuzzData)
{
    InitKeyNegotiationRequest request;
    request.hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    Attributes attr;
    (void)EncodeInitKeyNegotiationRequest(request, attr);
}

static void FuzzDecodeInitKeyNegotiationRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeInitKeyNegotiationRequest(attr);
    (void)result;
}

static void FuzzEncodeInitKeyNegotiationReply(FuzzedDataProvider &fuzzData)
{
    InitKeyNegotiationReply reply;
    reply.result = GenerateFuzzResultCode(fuzzData);
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    Attributes attr;
    (void)EncodeInitKeyNegotiationReply(reply, attr);
}

static void FuzzDecodeInitKeyNegotiationReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeInitKeyNegotiationReply(attr);
    (void)result;
}

static void FuzzEncodeBeginAddHostBindingRequest(FuzzedDataProvider &fuzzData)
{
    BeginAddHostBindingRequest request;
    request.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    Attributes attr;
    (void)EncodeBeginAddHostBindingRequest(request, attr);
}

static void FuzzDecodeBeginAddHostBindingRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeBeginAddHostBindingRequest(attr);
    (void)result;
}

static void FuzzEncodeBeginAddHostBindingReply(FuzzedDataProvider &fuzzData)
{
    BeginAddHostBindingReply reply;
    reply.result = GenerateFuzzResultCode(fuzzData);
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    Attributes attr;
    (void)EncodeBeginAddHostBindingReply(reply, attr);
}

static void FuzzDecodeBeginAddHostBindingReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeBeginAddHostBindingReply(attr);
    (void)result;
}

static void FuzzEncodeEndAddHostBindingRequest(FuzzedDataProvider &fuzzData)
{
    EndAddHostBindingRequest request;
    request.hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    request.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.result = GenerateFuzzResultCode(fuzzData);
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    Attributes attr;
    (void)EncodeEndAddHostBindingRequest(request, attr);
}

static void FuzzDecodeEndAddHostBindingRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeEndAddHostBindingRequest(attr);
    (void)result;
}

static void FuzzEncodeEndAddHostBindingReply(FuzzedDataProvider &fuzzData)
{
    EndAddHostBindingReply reply;
    reply.result = GenerateFuzzResultCode(fuzzData);
    Attributes attr;
    (void)EncodeEndAddHostBindingReply(reply, attr);
}

static void FuzzDecodeEndAddHostBindingReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeEndAddHostBindingReply(attr);
    (void)result;
}

static const AddCompanionMessageFuzzFunction g_fuzzFuncs[] = {
    FuzzEncodeInitKeyNegotiationRequest,
    FuzzDecodeInitKeyNegotiationRequest,
    FuzzEncodeInitKeyNegotiationReply,
    FuzzDecodeInitKeyNegotiationReply,
    FuzzEncodeBeginAddHostBindingRequest,
    FuzzDecodeBeginAddHostBindingRequest,
    FuzzEncodeBeginAddHostBindingReply,
    FuzzDecodeBeginAddHostBindingReply,
    FuzzEncodeEndAddHostBindingRequest,
    FuzzDecodeEndAddHostBindingRequest,
    FuzzEncodeEndAddHostBindingReply,
    FuzzDecodeEndAddHostBindingReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(AddCompanionMessageFuzzFunction);

void FuzzAddCompanionMessage(FuzzedDataProvider &fuzzData)
{
    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);

        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzAddCompanionMessage)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
