/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "adapter_initializer.h"
#include "blocked_state_sync_scheduler.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using BlockedStateSyncSchedulerFuzzFunction = void (*)(std::shared_ptr<BlockedStateSyncScheduler> &sched,
    FuzzedDataProvider &fuzzData);

static void FuzzUserAuthReady(std::shared_ptr<BlockedStateSyncScheduler> &sched, FuzzedDataProvider &)
{
    sched->OnUserAuthServiceReady();
}

static void FuzzUserAuthUnavailable(std::shared_ptr<BlockedStateSyncScheduler> &sched, FuzzedDataProvider &)
{
    sched->OnUserAuthServiceUnavailable();
}

static void FuzzPinReady(std::shared_ptr<BlockedStateSyncScheduler> &sched, FuzzedDataProvider &)
{
    sched->OnPinAuthServiceReady();
}

static void FuzzPinUnavailable(std::shared_ptr<BlockedStateSyncScheduler> &sched, FuzzedDataProvider &)
{
    sched->OnPinAuthServiceUnavailable();
}

static void FuzzActiveUserChange(std::shared_ptr<BlockedStateSyncScheduler> &sched, FuzzedDataProvider &fuzzData)
{
    (void)sched;
    FireFuzzActiveUserIdChange(fuzzData.ConsumeIntegral<int32_t>());
}

static const BlockedStateSyncSchedulerFuzzFunction g_fuzzFuncs[] = {
    FuzzUserAuthReady,
    FuzzUserAuthUnavailable,
    FuzzPinReady,
    FuzzPinUnavailable,
    FuzzActiveUserChange,
};
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(BlockedStateSyncSchedulerFuzzFunction);

void FuzzBlockedStateSyncScheduler(FuzzedDataProvider &fuzzData)
{
    auto sched = BlockedStateSyncScheduler::Create();
    if (sched == nullptr) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](sched, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](sched, fuzzData);
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzBlockedStateSyncScheduler)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
