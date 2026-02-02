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
#include "misc_manager_impl.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr int32_t INT32_3 = 3;
constexpr int32_t INT32_10 = 10;
} // namespace

using MiscManagerImplFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreate(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = MiscManagerImpl::Create();
    (void)manager;
}

static void FuzzGetNextGlobalId(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = MiscManagerImpl::Create();
    int num = INT32_10;
    if (manager) {
        for (int i = 0; i < num; ++i) {
            (void)manager->GetNextGlobalId();
        }
    }
}

static void FuzzGetLocalUdid(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        auto udid = manager->GetLocalUdid();
        (void)udid;
    }
}

static void FuzzClearDeviceSelectCallback(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        manager->ClearDeviceSelectCallback(tokenId);
    }
}

static void FuzzSetDeviceSelectCallback(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        // Cannot test SetDeviceSelectCallback without sptr<IIpcDeviceSelectCallback>
        (void)tokenId;
    }
}

static void FuzzGetDeviceSelectResult(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    uint8_t purposeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_3);
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        // Cannot test GetDeviceSelectResult without callback
        (void)tokenId;
        (void)purposeValue;
    }
}

static void FuzzMiscManagerImplConstructor(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = std::make_shared<MiscManagerImpl>();
    (void)manager;
}

static const MiscManagerImplFuzzFunction g_fuzzFuncs[] = {
    FuzzCreate,
    FuzzGetNextGlobalId,
    FuzzGetLocalUdid,
    FuzzClearDeviceSelectCallback,
    FuzzSetDeviceSelectCallback,
    FuzzGetDeviceSelectResult,
    FuzzMiscManagerImplConstructor,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(MiscManagerImplFuzzFunction);

void FuzzMiscManagerImpl(FuzzedDataProvider &fuzzData)
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

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzMiscManagerImpl)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
