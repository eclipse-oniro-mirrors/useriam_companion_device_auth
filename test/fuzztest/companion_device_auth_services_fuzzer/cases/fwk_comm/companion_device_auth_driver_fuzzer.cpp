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

#include "companion_auth_interface_adapter.h"
#include "companion_device_auth_driver.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(std::shared_ptr<CompanionDeviceAuthDriver> &drv, FuzzedDataProvider &);

static void FuzzOp0(std::shared_ptr<CompanionDeviceAuthDriver> &drv, FuzzedDataProvider &fuzzData)
{
    // Test GetExecutorList
    std::vector<std::shared_ptr<FwkIAuthExecutorHdi>> executorList;
    drv->GetExecutorList(executorList);
}

static void FuzzOp1(std::shared_ptr<CompanionDeviceAuthDriver> &drv, FuzzedDataProvider &fuzzData)
{
    // Test OnHdiDisconnect
    drv->OnHdiDisconnect();
}

static const FuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzCompanionDeviceAuthDriver(FuzzedDataProvider &fuzzData)
{
    auto adapter = std::make_shared<CompanionAuthInterfaceAdapter>();
    auto driver = std::make_shared<CompanionDeviceAuthDriver>(adapter);
    if (!driver) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](driver, fuzzData);
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
