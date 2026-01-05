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
#include "misc_manager_impl.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

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
    int num = 10;
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
    uint8_t purposeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 3);
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        // Cannot test GetDeviceSelectResult without callback
        (void)tokenId;
        (void)purposeValue;
    }
}

static void FuzzCheckBusinessIds(FuzzedDataProvider &fuzzData)
{
    uint32_t testVal100 = 100;
    std::vector<int32_t> businessIds = GenerateFuzzVector<int32_t>(fuzzData, testVal100);
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        (void)manager->CheckBusinessIds(businessIds);
    }
}

static void FuzzMiscManagerImplConstructor(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = std::make_shared<MiscManagerImpl>();
    (void)manager;
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzCreate,
    FuzzGetNextGlobalId,
    FuzzGetLocalUdid,
    FuzzClearDeviceSelectCallback,
    FuzzSetDeviceSelectCallback,
    FuzzGetDeviceSelectResult,
    FuzzCheckBusinessIds,
    FuzzMiscManagerImplConstructor,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzMiscManagerImpl(FuzzedDataProvider &fuzzData)
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

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
