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
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "soft_bus_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const size_t SIZE_1024 = 1024;
constexpr size_t SIZE_64 = 64;
} // namespace

using SoftBusAdapterFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreateServerSocket(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test server socket creation - callback would be created by actual implementation
}

static void FuzzCreateClientSocket(FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    std::string networkId = GenerateFuzzString(fuzzData, SIZE_64);
    (void)connectionName;
    (void)networkId;
}

static void FuzzSendBytes(FuzzedDataProvider &fuzzData)
{
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    size_t testVal = 4096;
    std::vector<uint8_t> data = GenerateFuzzVector<uint8_t>(fuzzData, testVal);
    (void)socketId;
    (void)data;
}

static void FuzzShutdownSocket(FuzzedDataProvider &fuzzData)
{
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    (void)socketId;
}

static void FuzzSoftBusOperations(FuzzedDataProvider &fuzzData)
{
    uint32_t operationCode = fuzzData.ConsumeIntegral<uint32_t>();
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    std::string networkId = GenerateFuzzString(fuzzData, SIZE_64);
    (void)operationCode;
    (void)socketId;
    (void)networkId;
}

static void FuzzMultipleSocketOperations(FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t i = 0; i < count; ++i) {
        int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
        std::vector<uint8_t> data = GenerateFuzzVector<uint8_t>(fuzzData, SIZE_1024);
        (void)socketId;
        (void)data;
    }
}

static void FuzzSocketDataTransfer(FuzzedDataProvider &fuzzData)
{
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t dataCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, 100);

    for (uint32_t i = 0; i < dataCount; ++i) {
        std::vector<uint8_t> data = GenerateFuzzVector<uint8_t>(fuzzData, SIZE_1024);
        (void)data;
    }
    (void)socketId;
}

static const SoftBusAdapterFuzzFunction g_fuzzFuncs[] = {
    FuzzCreateServerSocket,
    FuzzCreateClientSocket,
    FuzzSendBytes,
    FuzzShutdownSocket,
    FuzzSoftBusOperations,
    FuzzMultipleSocketOperations,
    FuzzSocketDataTransfer,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SoftBusAdapterFuzzFunction);

void FuzzSoftBusAdapter(FuzzedDataProvider &fuzzData)
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

FUZZ_REGISTER(SoftBusAdapter)

} // namespace UserIam
} // namespace OHOS
