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
#include "obtain_token_message.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const uint32_t TEST_VAL64 = 64;
}

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzEncodePreObtainTokenRequest(FuzzedDataProvider &fuzzData)
{
    PreObtainTokenRequest request;
    request.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.companionDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    request.companionDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    request.companionDeviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodePreObtainTokenRequest(request, attr);
}

static void FuzzDecodePreObtainTokenRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    PreObtainTokenRequest request;
    DecodePreObtainTokenRequest(attr, request);
}

static void FuzzEncodePreObtainTokenReply(FuzzedDataProvider &fuzzData)
{
    PreObtainTokenReply reply;
    reply.result = fuzzData.ConsumeIntegral<int32_t>();
    reply.requestId = fuzzData.ConsumeIntegral<uint64_t>();
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodePreObtainTokenReply(reply, attr);
}

static void FuzzDecodePreObtainTokenReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    PreObtainTokenReply reply;
    DecodePreObtainTokenReply(attr, reply);
}

static void FuzzEncodeObtainTokenRequest(FuzzedDataProvider &fuzzData)
{
    ObtainTokenRequest request;
    request.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.requestId = fuzzData.ConsumeIntegral<uint64_t>();
    request.companionDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    request.companionDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    request.companionDeviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodeObtainTokenRequest(request, attr);
}

static void FuzzDecodeObtainTokenRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    ObtainTokenRequest request;
    DecodeObtainTokenRequest(attr, request);
}

static void FuzzEncodeObtainTokenReply(FuzzedDataProvider &fuzzData)
{
    ObtainTokenReply reply;
    reply.result = fuzzData.ConsumeIntegral<int32_t>();
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodeObtainTokenReply(reply, attr);
}

static void FuzzDecodeObtainTokenReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    ObtainTokenReply reply;
    DecodeObtainTokenReply(attr, reply);
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzEncodePreObtainTokenRequest,
    FuzzDecodePreObtainTokenRequest,
    FuzzEncodePreObtainTokenReply,
    FuzzDecodePreObtainTokenReply,
    FuzzEncodeObtainTokenRequest,
    FuzzDecodeObtainTokenRequest,
    FuzzEncodeObtainTokenReply,
    FuzzDecodeObtainTokenReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzObtainTokenMessage(FuzzedDataProvider &fuzzData)
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
} // namespace UserIam
} // namespace OHOS
