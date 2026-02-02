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
#include "subscription_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SubscriptionManagerFuzzFunction = void (*)(std::shared_ptr<SubscriptionManager> &, FuzzedDataProvider &);

static void FuzzOp0(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetOrCreateAvailableDeviceSubscription
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    auto subscription = manager->GetOrCreateAvailableDeviceSubscription(userId);
    (void)subscription;
}

static void FuzzOp1(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetOrCreateTemplateStatusSubscription
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    auto subscription = manager->GetOrCreateTemplateStatusSubscription(userId);
    (void)subscription;
}

static void FuzzOp2(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetOrCreateContinuousAuthSubscription
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    std::optional<uint64_t> templateId;
    if (fuzzData.ConsumeBool()) {
        templateId = fuzzData.ConsumeIntegral<uint64_t>();
    }
    auto subscription = manager->GetOrCreateContinuousAuthSubscription(userId, templateId);
    (void)subscription;
}

static void FuzzOp3(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test AddAvailableDeviceStatusCallback with nullptr
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    manager->AddAvailableDeviceStatusCallback(userId, nullptr);
}

static void FuzzOp4(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test RemoveAvailableDeviceStatusCallback with nullptr
    manager->RemoveAvailableDeviceStatusCallback(nullptr);
}

static void FuzzOp5(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test AddTemplateStatusCallback with nullptr
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    manager->AddTemplateStatusCallback(userId, nullptr);
}

static void FuzzOp6(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test RemoveTemplateStatusCallback with nullptr
    manager->RemoveTemplateStatusCallback(nullptr);
}

static void FuzzOp7(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test AddContinuousAuthStatusCallback with nullptr
    int32_t userId = fuzzData.ConsumeIntegral<int32_t>();
    std::optional<uint64_t> templateId;
    if (fuzzData.ConsumeBool()) {
        templateId = fuzzData.ConsumeIntegral<uint64_t>();
    }
    manager->AddContinuousAuthStatusCallback(userId, templateId, nullptr);
}

static void FuzzOp8(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test RemoveContinuousAuthStatusCallback with nullptr
    manager->RemoveContinuousAuthStatusCallback(nullptr);
}

static void FuzzOp9(std::shared_ptr<SubscriptionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test UpdateSubscribeMode
    manager->UpdateSubscribeMode();
}

static const SubscriptionManagerFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4, FuzzOp5,
    FuzzOp6, FuzzOp7, FuzzOp8, FuzzOp9 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SubscriptionManagerFuzzFunction);

void FuzzSubscriptionManager(FuzzedDataProvider &fuzzData)
{
    // Create SubscriptionManager instance
    auto manager = std::make_shared<SubscriptionManager>();
    if (!manager) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](manager, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](manager, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzSubscriptionManager)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
