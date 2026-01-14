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
#include "soft_bus_connection_manager.h"
#include "soft_bus_socket.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
const uint32_t TEST_VAL64 = 64;
}

using SoftBusSocketFuzzFunction = void (*)(std::unique_ptr<SoftBusSocket> &, FuzzedDataProvider &);

static void FuzzOp0(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetSocketId
    (void)socket->GetSocketId();
}

static void FuzzOp1(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test IsConnected
    (void)socket->IsConnected();
}

static void FuzzOp2(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test IsInbound
    (void)socket->IsInbound();
}

static void FuzzOp3(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SetConnectionName
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    socket->SetConnectionName(connectionName);
}

static void FuzzOp4(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SetCloseReason
    std::string reason = GenerateFuzzString(fuzzData, 128);
    socket->SetCloseReason(reason);
}

static void FuzzOp5(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleOutboundConnected
    socket->HandleOutboundConnected();
}

static void FuzzOp6(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleInboundConnected
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    socket->HandleInboundConnected(connectionName);
}

static void FuzzOp7(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test MarkShutdownByPeer
    socket->MarkShutdownByPeer();
}

static void FuzzOp8(std::unique_ptr<SoftBusSocket> &socket, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetConnectionName and GetPhysicalDeviceKey
    (void)socket->GetConnectionName();
    (void)socket->GetPhysicalDeviceKey();
}

static const SoftBusSocketFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4, FuzzOp5, FuzzOp6,
    FuzzOp7, FuzzOp8 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SoftBusSocketFuzzFunction);

void FuzzSoftBusSocket(FuzzedDataProvider &fuzzData)
{
    // Create a connection manager for the socket
    auto manager = SoftBusConnectionManager::Create();
    if (!manager) {
        return;
    }

    // Create SoftBusSocket instance (outbound connection)
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);

    auto socket =
        std::make_unique<SoftBusSocket>(socketId, physicalKey, std::weak_ptr<SoftBusConnectionManager>(manager));

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](socket, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(SoftBusSocket)

} // namespace UserIam
} // namespace OHOS
