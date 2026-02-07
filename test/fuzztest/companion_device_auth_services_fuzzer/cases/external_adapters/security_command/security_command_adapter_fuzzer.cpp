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
#include "security_command_adapter_impl.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SecurityCommandFuzzFunction = void (*)(std::shared_ptr<SecurityCommandAdapterImpl> &adapter,
    FuzzedDataProvider &fuzzData);

static void FuzzInitialize(std::shared_ptr<SecurityCommandAdapterImpl> &adapter, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)adapter->Initialize();
}

static void FuzzInvokeCommand(std::shared_ptr<SecurityCommandAdapterImpl> &adapter, FuzzedDataProvider &fuzzData)
{
    int32_t commandId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t inputDataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> inputData = fuzzData.ConsumeBytes<uint8_t>(inputDataLen);

    uint32_t outputDataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> outputData(outputDataLen);

    (void)adapter->InvokeCommand(commandId, inputData.data(), inputDataLen, outputData.data(), outputDataLen);
}

static void FuzzInvokeCommandWithNullInput(std::shared_ptr<SecurityCommandAdapterImpl> &adapter,
    FuzzedDataProvider &fuzzData)
{
    int32_t commandId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t outputDataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> outputData(outputDataLen);

    (void)adapter->InvokeCommand(commandId, nullptr, 0, outputData.data(), outputDataLen);
}

static void FuzzInvokeCommandWithNullOutput(std::shared_ptr<SecurityCommandAdapterImpl> &adapter,
    FuzzedDataProvider &fuzzData)
{
    int32_t commandId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t inputDataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> inputData = fuzzData.ConsumeBytes<uint8_t>(inputDataLen);

    (void)adapter->InvokeCommand(commandId, inputData.data(), inputDataLen, nullptr, 0);
}

static void FuzzMultipleInitializes(std::shared_ptr<SecurityCommandAdapterImpl> &adapter, FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t i = 0; i < count; ++i) {
        (void)adapter->Initialize();
    }
}

static const SecurityCommandFuzzFunction g_fuzzFuncs[] = {
    FuzzInitialize,
    FuzzInvokeCommand,
    FuzzInvokeCommandWithNullInput,
    FuzzInvokeCommandWithNullOutput,
    FuzzMultipleInitializes,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SecurityCommandFuzzFunction);

constexpr int32_t INT32_100 = 100;

void FuzzSecurityCommandAdapter(FuzzedDataProvider &fuzzData)
{
    auto adapter = SecurityCommandAdapterImpl::Create();
    if (!adapter) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](adapter, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = INT32_100;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](adapter, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzSecurityCommandAdapter)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
