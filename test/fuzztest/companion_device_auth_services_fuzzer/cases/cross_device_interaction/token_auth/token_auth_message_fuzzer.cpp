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
#include "token_auth_message.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using TokenAuthMessageFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzEncodeTokenAuthRequest(FuzzedDataProvider &fuzzData)
{
    TokenAuthRequest request;
    request.hostDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    uint32_t testVal64 = TEST_VAL64;
    request.hostDeviceKey.deviceId = GenerateFuzzString(fuzzData, testVal64);
    request.hostDeviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodeTokenAuthRequest(request, attr);
}

static void FuzzDecodeTokenAuthRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeTokenAuthRequest(attr);
    (void)result;
}

static void FuzzEncodeTokenAuthReply(FuzzedDataProvider &fuzzData)
{
    TokenAuthReply reply;
    reply.result = static_cast<ResultCode>(fuzzData.ConsumeIntegralInRange<uint32_t>(
        static_cast<uint32_t>(ResultCode::SUCCESS), static_cast<uint32_t>(ResultCode::GENERAL_ERROR)));
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodeTokenAuthReply(reply, attr);
}

static void FuzzDecodeTokenAuthReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeTokenAuthReply(attr);
    (void)result;
}

static const TokenAuthMessageFuzzFunction g_fuzzFuncs[] = {
    FuzzEncodeTokenAuthRequest,
    FuzzDecodeTokenAuthRequest,
    FuzzEncodeTokenAuthReply,
    FuzzDecodeTokenAuthReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(TokenAuthMessageFuzzFunction);

void FuzzTokenAuthMessage(FuzzedDataProvider &fuzzData)
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
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzTokenAuthMessage)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
