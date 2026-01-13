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

#include "delegate_auth_message.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using DelegateAuthMessageFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzEncodeStartDelegateAuthRequest(FuzzedDataProvider &fuzzData)
{
    StartDelegateAuthRequest request;
    request.hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    request.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    Attributes attr;
    (void)EncodeStartDelegateAuthRequest(request, attr);
}

static void FuzzDecodeStartDelegateAuthRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeStartDelegateAuthRequest(attr);
    (void)result;
}

static void FuzzEncodeStartDelegateAuthReply(FuzzedDataProvider &fuzzData)
{
    StartDelegateAuthReply reply;
    reply.result = GenerateFuzzResultCode(fuzzData);
    Attributes attr;
    (void)EncodeStartDelegateAuthReply(reply, attr);
}

static void FuzzDecodeStartDelegateAuthReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeStartDelegateAuthReply(attr);
    (void)result;
}

static void FuzzEncodeSendDelegateAuthResultRequest(FuzzedDataProvider &fuzzData)
{
    SendDelegateAuthResultRequest request;
    request.result = GenerateFuzzResultCode(fuzzData);
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    Attributes attr;
    (void)EncodeSendDelegateAuthResultRequest(request, attr);
}

static void FuzzDecodeSendDelegateAuthResultRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeSendDelegateAuthResultRequest(attr);
    (void)result;
}

static void FuzzEncodeSendDelegateAuthResultReply(FuzzedDataProvider &fuzzData)
{
    SendDelegateAuthResultReply reply;
    reply.result = GenerateFuzzResultCode(fuzzData);
    Attributes attr;
    (void)EncodeSendDelegateAuthResultReply(reply, attr);
}

static void FuzzDecodeSendDelegateAuthResultReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeSendDelegateAuthResultReply(attr);
    (void)result;
}

static const DelegateAuthMessageFuzzFunction g_fuzzFuncs[] = {
    FuzzEncodeStartDelegateAuthRequest,
    FuzzDecodeStartDelegateAuthRequest,
    FuzzEncodeStartDelegateAuthReply,
    FuzzDecodeStartDelegateAuthReply,
    FuzzEncodeSendDelegateAuthResultRequest,
    FuzzDecodeSendDelegateAuthResultRequest,
    FuzzEncodeSendDelegateAuthResultReply,
    FuzzDecodeSendDelegateAuthResultReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(DelegateAuthMessageFuzzFunction);

void FuzzDelegateAuthMessage(FuzzedDataProvider &fuzzData)
{
    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);

        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(DelegateAuthMessage)

} // namespace UserIam
} // namespace OHOS
