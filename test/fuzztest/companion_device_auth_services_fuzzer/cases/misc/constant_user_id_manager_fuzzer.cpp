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

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreate(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = IUserIdManager::Create();
    (void)manager;
}

static void FuzzGetActiveUserId(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = IUserIdManager::Create();
    if (manager) {
        auto userId = manager->GetActiveUserId();
        (void)userId;
    }
}

static void FuzzGetActiveUserName(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = IUserIdManager::Create();
    if (manager) {
        auto userName = manager->GetActiveUserName();
        (void)userName;
    }
}

static void FuzzSubscribeActiveUserId(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = IUserIdManager::Create();
    if (manager) {
        auto callback = [](int32_t userId) { (void)userId; };
        auto subscription = manager->SubscribeActiveUserId(std::move(callback));
        (void)subscription;
        EnsureAllTaskExecuted();
    }
}

static void FuzzIsUserIdValid(FuzzedDataProvider &fuzzData)
{
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    auto manager = IUserIdManager::Create();
    if (manager) {
        auto valid = manager->IsUserIdValid(userId);
        (void)valid;
    }
}

static void FuzzMultipleCreate(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    const int32_t createLimit = 5;
    for (int i = 0; i < createLimit; ++i) {
        auto manager = IUserIdManager::Create();
        (void)manager;
    }
}

static void FuzzCreateAndTestAll(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = IUserIdManager::Create();
    if (manager) {
        auto userId = manager->GetActiveUserId();
        auto userName = manager->GetActiveUserName();
        auto valid = manager->IsUserIdValid(userId);
        auto valid2 = manager->IsUserIdValid(userId + 1);
        (void)userName;
        (void)valid;
        (void)valid2;
    }
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzCreate,
    FuzzGetActiveUserId,
    FuzzGetActiveUserName,
    FuzzSubscribeActiveUserId,
    FuzzIsUserIdValid,
    FuzzMultipleCreate,
    FuzzCreateAndTestAll,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzConstantUserIdManager(FuzzedDataProvider &fuzzData)
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
