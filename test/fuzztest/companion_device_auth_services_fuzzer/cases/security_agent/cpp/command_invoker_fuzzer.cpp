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

#include "command_invoker.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(std::shared_ptr<CommandInvoker> &invoker, FuzzedDataProvider &fuzzData);

static void FuzzInitialize(std::shared_ptr<CommandInvoker> &invoker, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)invoker->Initialize();
}

static void FuzzFinalize(std::shared_ptr<CommandInvoker> &invoker, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    invoker->Finalize();
}

static void FuzzInvokeCommand(std::shared_ptr<CommandInvoker> &invoker, FuzzedDataProvider &fuzzData)
{
    int32_t commandId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t inputDataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> inputData = fuzzData.ConsumeBytes<uint8_t>(inputDataLen);

    uint32_t outputDataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> outputData(outputDataLen);

    (void)invoker->InvokeCommand(commandId, inputData.data(), inputDataLen, outputData.data(), outputDataLen);
}

static void FuzzInvokeCommandWithNullInput(std::shared_ptr<CommandInvoker> &invoker, FuzzedDataProvider &fuzzData)
{
    int32_t commandId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t outputDataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> outputData(outputDataLen);

    (void)invoker->InvokeCommand(commandId, nullptr, 0, outputData.data(), outputDataLen);
}

static void FuzzInvokeCommandWithNullOutput(std::shared_ptr<CommandInvoker> &invoker, FuzzedDataProvider &fuzzData)
{
    int32_t commandId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t inputDataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> inputData = fuzzData.ConsumeBytes<uint8_t>(inputDataLen);

    (void)invoker->InvokeCommand(commandId, inputData.data(), inputDataLen, nullptr, 0);
}

static void FuzzMultipleInitializes(std::shared_ptr<CommandInvoker> &invoker, FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t i = 0; i < count; ++i) {
        (void)invoker->Initialize();
    }
}

static void FuzzInitializeFinalizeSequence(std::shared_ptr<CommandInvoker> &invoker, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)invoker->Initialize();
    invoker->Finalize();
    (void)invoker->Initialize();
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzInitialize,
    FuzzFinalize,
    FuzzInvokeCommand,
    FuzzInvokeCommandWithNullInput,
    FuzzInvokeCommandWithNullOutput,
    FuzzMultipleInitializes,
    FuzzInitializeFinalizeSequence,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzCommandInvoker(FuzzedDataProvider &fuzzData)
{
    auto invoker = std::make_shared<CommandInvoker>();
    if (!invoker) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](invoker, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
