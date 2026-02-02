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
#include "incoming_message_handler_registry.h"
#include "singleton_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

constexpr int32_t INT32_10 = 10;

using IncomingMessageHandlerRegistryFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreate(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    (void)registry;
    (void)fuzzData;
}

static void FuzzCreateAndRegister(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    if (registry) {
        registry->RegisterHandlers();
    }
    (void)fuzzData;
}

static void FuzzMultipleCreate(FuzzedDataProvider &fuzzData)
{
    auto reg1 = IncomingMessageHandlerRegistry::Create();
    auto reg2 = IncomingMessageHandlerRegistry::Create();
    auto reg3 = IncomingMessageHandlerRegistry::Create();
    (void)reg1;
    (void)reg2;
    (void)reg3;
    (void)fuzzData;
}

static void FuzzCreateWithNullCheck(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    if (registry != nullptr) {
        bool registerResult = registry->RegisterHandlers();
        (void)registerResult;
    }
    (void)fuzzData;
}

static void FuzzCreateLoop(FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_10);
    for (uint8_t i = 0; i < count; ++i) {
        auto registry = IncomingMessageHandlerRegistry::Create();
        (void)registry;
    }
    (void)fuzzData;
}

static void FuzzRegisterTwice(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    if (registry) {
        registry->RegisterHandlers();
        registry->RegisterHandlers();
    }
    (void)fuzzData;
}

static void FuzzCreateWithoutOperations(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    (void)registry;
    (void)fuzzData;
}

static const IncomingMessageHandlerRegistryFuzzFunction g_fuzzFuncs[] = {
    FuzzCreate,
    FuzzCreateAndRegister,
    FuzzMultipleCreate,
    FuzzCreateWithNullCheck,
    FuzzCreateLoop,
    FuzzRegisterTwice,
    FuzzCreateWithoutOperations,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(IncomingMessageHandlerRegistryFuzzFunction);

void FuzzIncomingMessageHandlerRegistry(FuzzedDataProvider &fuzzData)
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

FUZZ_REGISTER(FuzzIncomingMessageHandlerRegistry)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
