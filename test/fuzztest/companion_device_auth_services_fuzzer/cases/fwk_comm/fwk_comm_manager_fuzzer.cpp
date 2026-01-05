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
#include "fwk_comm_manager.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreate(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = FwkCommManager::Create();
    (void)manager;
}

static void FuzzCreateMultiple(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    int num = 3;
    for (int i = 0; i < num; ++i) {
        auto manager = FwkCommManager::Create();
        (void)manager;
    }
}

static void FuzzCreateUserId(FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    (void)userId;
}

static void FuzzGenerateMessage(FuzzedDataProvider &fuzzData)
{
    uint32_t msgSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> msg = fuzzData.ConsumeBytes<uint8_t>(msgSize);
    (void)msg;
}

static void FuzzCreateResultCallback(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto resultCallback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    (void)resultCallback;
}

static void FuzzInvokeResultCallback(FuzzedDataProvider &fuzzData)
{
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    uint32_t dataSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> extraInfo = fuzzData.ConsumeBytes<uint8_t>(dataSize);

    auto resultCallback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    resultCallback(result, extraInfo);
}

static void FuzzGenerateAttributes(FuzzedDataProvider &fuzzData)
{
    auto attributes = GenerateFuzzAttributes(fuzzData);
    (void)attributes;
}

static void FuzzGenerateAttributesWithLimit(FuzzedDataProvider &fuzzData)
{
    uint8_t attrCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_ATTRIBUTES_COUNT);
    auto attributes = GenerateFuzzAttributes(fuzzData, attrCount);
    (void)attributes;
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzCreate,
    FuzzCreateMultiple,
    FuzzCreateUserId,
    FuzzGenerateMessage,
    FuzzCreateResultCallback,
    FuzzInvokeResultCallback,
    FuzzGenerateAttributes,
    FuzzGenerateAttributesWithLimit,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzFwkCommManager(FuzzedDataProvider &fuzzData)
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
