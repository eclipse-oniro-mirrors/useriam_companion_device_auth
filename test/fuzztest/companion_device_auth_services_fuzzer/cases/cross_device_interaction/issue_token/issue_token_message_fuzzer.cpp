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
#include "issue_token_message.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const uint32_t TEST_VAL64 = 64;
}

using IssueTokenMessageFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzEncodePreIssueTokenRequest(FuzzedDataProvider &fuzzData)
{
    PreIssueTokenRequest request;
    request.hostDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    request.hostDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    request.hostDeviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodePreIssueTokenRequest(request, attr);
}

static void FuzzDecodePreIssueTokenRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodePreIssueTokenRequest(attr);
    (void)result;
}

static void FuzzEncodePreIssueTokenReply(FuzzedDataProvider &fuzzData)
{
    PreIssueTokenReply reply;
    reply.result = static_cast<ResultCode>(fuzzData.ConsumeIntegralInRange<uint32_t>(
        static_cast<uint32_t>(ResultCode::SUCCESS), static_cast<uint32_t>(ResultCode::GENERAL_ERROR)));
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodePreIssueTokenReply(reply, attr);
}

static void FuzzDecodePreIssueTokenReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodePreIssueTokenReply(attr);
    (void)result;
}

static void FuzzEncodeIssueTokenRequest(FuzzedDataProvider &fuzzData)
{
    IssueTokenRequest request;
    request.hostDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    request.hostDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    request.hostDeviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.companionUserId = fuzzData.ConsumeIntegral<int32_t>();
    request.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodeIssueTokenRequest(request, attr);
}

static void FuzzDecodeIssueTokenRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeIssueTokenRequest(attr);
    (void)result;
}

static void FuzzEncodeIssueTokenReply(FuzzedDataProvider &fuzzData)
{
    IssueTokenReply reply;
    reply.result = static_cast<ResultCode>(fuzzData.ConsumeIntegralInRange<uint32_t>(
        static_cast<uint32_t>(ResultCode::SUCCESS), static_cast<uint32_t>(ResultCode::GENERAL_ERROR)));
    reply.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    Attributes attr;
    EncodeIssueTokenReply(reply, attr);
}

static void FuzzDecodeIssueTokenReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeIssueTokenReply(attr);
    (void)result;
}

static const IssueTokenMessageFuzzFunction g_fuzzFuncs[] = {
    FuzzEncodePreIssueTokenRequest,
    FuzzDecodePreIssueTokenRequest,
    FuzzEncodePreIssueTokenReply,
    FuzzDecodePreIssueTokenReply,
    FuzzEncodeIssueTokenRequest,
    FuzzDecodeIssueTokenRequest,
    FuzzEncodeIssueTokenReply,
    FuzzDecodeIssueTokenReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(IssueTokenMessageFuzzFunction);

void FuzzIssueTokenMessage(FuzzedDataProvider &fuzzData)
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

FUZZ_REGISTER(IssueTokenMessage)

} // namespace UserIam
} // namespace OHOS
