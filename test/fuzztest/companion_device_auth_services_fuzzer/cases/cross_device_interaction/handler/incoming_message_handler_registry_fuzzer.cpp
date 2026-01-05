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
#include "incoming_message_handler_registry.h"
#include "service_fuzz_entry.h"
#include "singleton_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreate(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    (void)registry;
    (void)fuzzData;
}

static void FuzzCreateAndInitialize(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    if (registry) {
        registry->Initialize();
    }
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

static void FuzzCreateFull(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    if (registry) {
        registry->Initialize();
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
        bool initResult = registry->Initialize();
        (void)initResult;
        bool registerResult = registry->RegisterHandlers();
        (void)registerResult;
    }
    (void)fuzzData;
}

static void FuzzCreateLoop(FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t i = 0; i < count; ++i) {
        auto registry = IncomingMessageHandlerRegistry::Create();
        if (registry) {
            registry->Initialize();
        }
    }
}

static void FuzzInitializeTwice(FuzzedDataProvider &fuzzData)
{
    auto registry = IncomingMessageHandlerRegistry::Create();
    if (registry) {
        registry->Initialize();
        registry->Initialize();
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

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzCreate,
    FuzzCreateAndInitialize,
    FuzzCreateAndRegister,
    FuzzCreateFull,
    FuzzMultipleCreate,
    FuzzCreateWithNullCheck,
    FuzzCreateLoop,
    FuzzInitializeTwice,
    FuzzRegisterTwice,
    FuzzCreateWithoutOperations,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzIncomingMessageHandlerRegistry(FuzzedDataProvider &fuzzData)
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
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
