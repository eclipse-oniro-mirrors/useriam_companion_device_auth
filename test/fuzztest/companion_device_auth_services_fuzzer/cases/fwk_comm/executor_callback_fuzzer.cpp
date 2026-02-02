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

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr int32_t INT32_5 = 5;

using ExecutorCallbackFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreateRequestCallback(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto callback = [](int32_t resultCode, const std::vector<uint8_t> &data) {
        (void)resultCode;
        (void)data;
    };
    (void)callback;
}

static void FuzzInvokeCallbackWithSuccess(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto callback = [](int32_t resultCode, const std::vector<uint8_t> &data) {
        (void)resultCode;
        (void)data;
    };
    callback(0, {});
}

static void FuzzInvokeCallbackWithFailure(FuzzedDataProvider &fuzzData)
{
    int32_t errorCode = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t dataSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> data = fuzzData.ConsumeBytes<uint8_t>(dataSize);

    auto callback = [](int32_t resultCode, const std::vector<uint8_t> &data) {
        (void)resultCode;
        (void)data;
    };
    callback(errorCode, data);
}

static void FuzzInvokeCallbackWithLargeData(FuzzedDataProvider &fuzzData)
{
    int32_t resultCode = fuzzData.ConsumeIntegral<int32_t>();
    std::vector<uint8_t> largeData(FUZZ_MAX_MESSAGE_LENGTH);

    auto callback = [](int32_t resultCode, const std::vector<uint8_t> &data) {
        (void)resultCode;
        (void)data;
    };
    callback(resultCode, largeData);
}

static void FuzzCreateMultipleCallbacks(FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_5);
    for (uint8_t i = 0; i < count; ++i) {
        auto callback = [](int32_t resultCode, const std::vector<uint8_t> &data) {
            (void)resultCode;
            (void)data;
        };
        (void)callback;
    }
}

static const ExecutorCallbackFuzzFunction g_fuzzFuncs[] = {
    FuzzCreateRequestCallback,
    FuzzInvokeCallbackWithSuccess,
    FuzzInvokeCallbackWithFailure,
    FuzzInvokeCallbackWithLargeData,
    FuzzCreateMultipleCallbacks,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(ExecutorCallbackFuzzFunction);

void FuzzExecutorCallback(FuzzedDataProvider &fuzzData)
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

FUZZ_REGISTER(FuzzExecutorCallback)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
