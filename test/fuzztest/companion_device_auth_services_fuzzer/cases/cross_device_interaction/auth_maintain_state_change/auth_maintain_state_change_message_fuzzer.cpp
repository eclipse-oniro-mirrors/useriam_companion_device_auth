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

#include "auth_maintain_state_change_message.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzEncodeAuthMaintainStateChangeRequest(FuzzedDataProvider &fuzzData)
{
    AuthMaintainStateChangeRequestMsg request;
    request.authMaintainState = fuzzData.ConsumeBool();

    Attributes attr;
    EncodeAuthMaintainStateChangeRequest(request, attr);
}

static void FuzzDecodeAuthMaintainStateChangeRequest(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeAuthMaintainStateChangeRequest(attr);
    (void)result;
}

static void FuzzEncodeAuthMaintainStateChangeReply(FuzzedDataProvider &fuzzData)
{
    AuthMaintainStateChangeReplyMsg reply;
    reply.result = static_cast<ResultCode>(fuzzData.ConsumeIntegralInRange<uint32_t>(
        static_cast<uint32_t>(ResultCode::SUCCESS), static_cast<uint32_t>(ResultCode::GENERAL_ERROR)));

    Attributes attr;
    EncodeAuthMaintainStateChangeReply(reply, attr);
}

static void FuzzDecodeAuthMaintainStateChangeReply(FuzzedDataProvider &fuzzData)
{
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    auto result = DecodeAuthMaintainStateChangeReply(attr);
    (void)result;
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzEncodeAuthMaintainStateChangeRequest,
    FuzzDecodeAuthMaintainStateChangeRequest,
    FuzzEncodeAuthMaintainStateChangeReply,
    FuzzDecodeAuthMaintainStateChangeReply,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzAuthMaintainStateChangeMessage(FuzzedDataProvider &fuzzData)
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
