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

#include "fuzzer/FuzzedDataProvider.h"

#include "backoff_retry_timer.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_50 = 50;
constexpr int32_t INT32_10 = 10;
constexpr int32_t INT32_10000 = 10000;
constexpr int32_t INT32_1000 = 1000;
constexpr int32_t INT32_60000 = 60000;

using BackoffRetryTimerFuzzFunction = void (*)(std::shared_ptr<BackoffRetryTimer> &timer, FuzzedDataProvider &fuzzData);

static void FuzzOnFailure(std::shared_ptr<BackoffRetryTimer> &timer, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (timer) {
        timer->OnFailure();
    }
}

static void FuzzReset(std::shared_ptr<BackoffRetryTimer> &timer, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (timer) {
        timer->Reset();
    }
}

static void FuzzGetFailureCount(std::shared_ptr<BackoffRetryTimer> &timer, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (timer) {
        auto count = timer->GetFailureCount();
        (void)count;
    }
}

static void FuzzCalculateNextDelayMs(std::shared_ptr<BackoffRetryTimer> &timer, FuzzedDataProvider &fuzzData)
{
    if (timer) {
        uint32_t failureCount = fuzzData.ConsumeIntegral<uint32_t>();
        BackoffRetryTimer::Config config;
        config.baseDelayMs = fuzzData.ConsumeIntegral<uint32_t>();
        config.maxDelayMs = fuzzData.ConsumeIntegral<uint32_t>();

        auto delay = BackoffRetryTimer::CalculateNextDelayMs(failureCount, config);
        (void)delay;
    }
}

static void FuzzOnFailureMultiple(std::shared_ptr<BackoffRetryTimer> &timer, FuzzedDataProvider &fuzzData)
{
    if (timer) {
        uint32_t failureCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, INT32_100);
        for (uint32_t i = 0; i < failureCount; ++i) {
            timer->OnFailure();
        }
    }
}

static void FuzzFailureResetCycle(std::shared_ptr<BackoffRetryTimer> &timer, FuzzedDataProvider &fuzzData)
{
    if (timer) {
        uint32_t failureCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, INT32_50);
        for (uint32_t i = 0; i < failureCount; ++i) {
            timer->OnFailure();
        }
        timer->Reset();

        // Test another cycle
        failureCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, INT32_50);
        for (uint32_t i = 0; i < failureCount; ++i) {
            timer->OnFailure();
        }
    }
}

static void FuzzCalculateNextDelayMsBoundary(std::shared_ptr<BackoffRetryTimer> &timer, FuzzedDataProvider &fuzzData)
{
    (void)timer;
    // Test boundary conditions for CalculateNextDelayMs
    std::vector<uint32_t> failureCounts = { 0, 1, INT32_10, INT32_100, UINT32_MAX };

    BackoffRetryTimer::Config config;
    config.baseDelayMs = fuzzData.ConsumeIntegralInRange<uint32_t>(1, INT32_10000);
    config.maxDelayMs = fuzzData.ConsumeIntegralInRange<uint32_t>(INT32_1000, INT32_60000);

    for (auto failureCount : failureCounts) {
        auto delay = BackoffRetryTimer::CalculateNextDelayMs(failureCount, config);
        (void)delay;
    }
}

static const BackoffRetryTimerFuzzFunction g_fuzzFuncs[] = {
    FuzzOnFailure,
    FuzzReset,
    FuzzGetFailureCount,
    FuzzCalculateNextDelayMs,
    FuzzOnFailureMultiple,
    FuzzFailureResetCycle,
    FuzzCalculateNextDelayMsBoundary,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(BackoffRetryTimerFuzzFunction);

void FuzzBackoffRetryTimer(FuzzedDataProvider &fuzzData)
{
    BackoffRetryTimer::Config config;
    config.baseDelayMs = fuzzData.ConsumeIntegralInRange<uint32_t>(1, INT32_10000);
    config.maxDelayMs = fuzzData.ConsumeIntegralInRange<uint32_t>(INT32_1000, INT32_60000);

    auto timer = std::make_shared<BackoffRetryTimer>(config, []() { });
    if (!timer) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](timer, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = INT32_100;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](timer, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzBackoffRetryTimer)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
