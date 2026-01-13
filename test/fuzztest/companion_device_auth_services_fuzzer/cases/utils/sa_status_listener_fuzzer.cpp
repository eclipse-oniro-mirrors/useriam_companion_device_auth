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
#include <new>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "sa_status_listener.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SaStatusListenerFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreateWithDefaultParams(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::string name = "TestSa";
    int32_t systemAbilityId = 1001;
    auto listener = SaStatusListener::Create(name, systemAbilityId, []() { (void)0; }, []() { (void)0; });
    (void)listener;
}

static void FuzzCreateWithFuzzedParams(FuzzedDataProvider &fuzzData)
{
    std::string name = GenerateFuzzString(fuzzData, 64);
    int32_t systemAbilityId = fuzzData.ConsumeIntegral<int32_t>();
    auto listener = SaStatusListener::Create(name, systemAbilityId, []() { (void)0; }, []() { (void)0; });
    (void)listener;
}

static void FuzzCreateWithEmptyName(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::string name;
    int32_t systemAbilityId = fuzzData.ConsumeIntegral<int32_t>();
    auto listener = SaStatusListener::Create(name, systemAbilityId, []() { (void)0; }, []() { (void)0; });
    (void)listener;
}

static void FuzzCreateWithNullCallbacks(FuzzedDataProvider &fuzzData)
{
    std::string name = GenerateFuzzString(fuzzData, 64);
    int32_t systemAbilityId = fuzzData.ConsumeIntegral<int32_t>();
    auto listener = SaStatusListener::Create(name, systemAbilityId, nullptr, nullptr);
    (void)listener;
}

static void FuzzMultipleCreates(FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t i = 0; i < count; ++i) {
        std::string name = "TestSa" + std::to_string(i);
        int32_t systemAbilityId = 1001 + i;
        auto listener = SaStatusListener::Create(name, systemAbilityId, []() { (void)0; }, []() { (void)0; });
        (void)listener;
    }
}

static void FuzzCreateWithLambdaCaptures(FuzzedDataProvider &fuzzData)
{
    int callCount = 0;
    std::string name = GenerateFuzzString(fuzzData, 64);
    int32_t systemAbilityId = fuzzData.ConsumeIntegral<int32_t>();

    SaStatusListener::AddFunc addFunc = [&callCount]() { callCount++; };
    SaStatusListener::RemoveFunc removeFunc = [&callCount]() { callCount--; };

    auto listener = SaStatusListener::Create(name, systemAbilityId, std::move(addFunc), std::move(removeFunc));
    (void)listener;
    (void)callCount;
}

static const SaStatusListenerFuzzFunction g_fuzzFuncs[] = {
    FuzzCreateWithDefaultParams,
    FuzzCreateWithFuzzedParams,
    FuzzCreateWithEmptyName,
    FuzzCreateWithNullCallbacks,
    FuzzMultipleCreates,
    FuzzCreateWithLambdaCaptures,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SaStatusListenerFuzzFunction);

void FuzzSaStatusListener(FuzzedDataProvider &fuzzData)
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

FUZZ_REGISTER(SaStatusListener)

} // namespace UserIam
} // namespace OHOS
