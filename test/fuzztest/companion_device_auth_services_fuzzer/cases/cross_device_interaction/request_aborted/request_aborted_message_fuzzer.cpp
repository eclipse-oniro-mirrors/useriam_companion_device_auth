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

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "request_aborted_message.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using RequestAbortedMessageFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzEncodeRequestAbortedRequest(FuzzedDataProvider &fuzzData)
{
    RequestAbortedRequest request;
    request.result = static_cast<ResultCode>(fuzzData.ConsumeIntegralInRange<uint32_t>(
        static_cast<uint32_t>(ResultCode::SUCCESS), static_cast<uint32_t>(ResultCode::GENERAL_ERROR)));
    uint32_t testVal256 = 256;
    request.reason = GenerateFuzzString(fuzzData, testVal256);

    Attributes attr;
    EncodeRequestAbortedRequest(request, attr);
}

static void FuzzDecodeRequestAbortedRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto requestOpt = DecodeRequestAbortedRequest(attr);
    (void)requestOpt;
}

static void FuzzEncodeRequestAbortedReply(FuzzedDataProvider &fuzzData)
{
    RequestAbortedReply reply;
    reply.result = static_cast<ResultCode>(fuzzData.ConsumeIntegralInRange<uint32_t>(
        static_cast<uint32_t>(ResultCode::SUCCESS), static_cast<uint32_t>(ResultCode::GENERAL_ERROR)));

    Attributes attr;
    EncodeRequestAbortedReply(reply, attr);
}

static void FuzzDecodeRequestAbortedReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto replyOpt = DecodeRequestAbortedReply(attr);
    (void)replyOpt;
}

static const RequestAbortedMessageFuzzFunction g_fuzzFuncs[] = {
    FuzzEncodeRequestAbortedRequest,
    FuzzDecodeRequestAbortedRequest,
    FuzzEncodeRequestAbortedReply,
    FuzzDecodeRequestAbortedReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(RequestAbortedMessageFuzzFunction);

void FuzzRequestAbortedMessage(FuzzedDataProvider &fuzzData)
{
    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(RequestAbortedMessage)

} // namespace UserIam
} // namespace OHOS
