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
#include "service_fuzz_entry.h"
#include "soft_bus_connection_manager.h"
#include "soft_bus_global_callbacks.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(SoftBusConnectionManager *manager, FuzzedDataProvider &);

static void FuzzOp0(SoftBusConnectionManager *manager, FuzzedDataProvider &fuzzData)
{
    // Test SoftBusOnBind
    int32_t socket = fuzzData.ConsumeIntegral<int32_t>();
    PeerSocketInfo info;
    char pkgName[] = "ohos.companiondeviceauth";
    char networkId[] = "test-network-id";
    info.pkgName = pkgName;
    info.networkId = networkId;
    SoftBusOnBind(socket, info);
}

static void FuzzOp1(SoftBusConnectionManager *manager, FuzzedDataProvider &fuzzData)
{
    // Test SoftBusOnShutdown
    int32_t socket = fuzzData.ConsumeIntegral<int32_t>();
    ShutdownReason reason = static_cast<ShutdownReason>(fuzzData.ConsumeIntegral<int32_t>());
    SoftBusOnShutdown(socket, reason);
}

static void FuzzOp2(SoftBusConnectionManager *manager, FuzzedDataProvider &fuzzData)
{
    // Test SoftBusOnBytes
    int32_t socket = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t dataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> data = fuzzData.ConsumeBytes<uint8_t>(dataLen);
    SoftBusOnBytes(socket, data.data(), dataLen);
}

static void FuzzOp3(SoftBusConnectionManager *manager, FuzzedDataProvider &fuzzData)
{
    // Test SoftBusOnError
    int32_t socket = fuzzData.ConsumeIntegral<int32_t>();
    int32_t errCode = fuzzData.ConsumeIntegral<int32_t>();
    SoftBusOnError(socket, errCode);
}

static void FuzzOp4(SoftBusConnectionManager *manager, FuzzedDataProvider &fuzzData)
{
    // Test SoftBusOnNegotiate
    int32_t socket = fuzzData.ConsumeIntegral<int32_t>();
    PeerSocketInfo info;
    char pkgName[] = "ohos.companiondeviceauth";
    char networkId[] = "test-network-id";
    info.pkgName = pkgName;
    info.networkId = networkId;
    (void)SoftBusOnNegotiate(socket, info);
}

static void FuzzOp5(SoftBusConnectionManager *manager, FuzzedDataProvider &fuzzData)
{
    // Test ClearGlobalSoftBusConnectionManager
    if (manager) {
        ClearGlobalSoftBusConnectionManager(manager);
    }
}

static const FuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4, FuzzOp5 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzSoftBusGlobalCallbacks(FuzzedDataProvider &fuzzData)
{
    // Create a connection manager for testing global callbacks
    auto manager = SoftBusConnectionManager::Create();
    SoftBusConnectionManager *managerPtr = manager.get();
    if (manager) {
        SetGlobalSoftBusConnectionManager(std::weak_ptr<SoftBusConnectionManager>(manager));
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](managerPtr, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
