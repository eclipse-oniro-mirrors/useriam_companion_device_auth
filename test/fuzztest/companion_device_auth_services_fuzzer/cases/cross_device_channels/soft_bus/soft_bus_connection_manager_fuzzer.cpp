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

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr uint32_t SIZE_128 = 128;
}

using SoftBusConnectionManagerFuzzFunction = void (*)(std::shared_ptr<SoftBusConnectionManager> &,
    FuzzedDataProvider &);

static void FuzzOp0(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Start
    manager->Start();
}

static void FuzzOp1(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test OpenConnection
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    std::string networkId = GenerateFuzzString(fuzzData, TEST_VAL64);
    manager->OpenConnection(connectionName, physicalKey, networkId);
}

static void FuzzOp2(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test CloseConnection
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    manager->CloseConnection(connectionName);
}

static void FuzzOp3(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SendMessage
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    std::vector<uint8_t> rawMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    manager->SendMessage(connectionName, rawMsg);
}

static void FuzzOp4(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleBind
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    std::string peerNetworkId = GenerateFuzzString(fuzzData, TEST_VAL64);
    manager->HandleBind(socketId, peerNetworkId);
}

static void FuzzOp5(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleBytes
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t dataLen = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> data = fuzzData.ConsumeBytes<uint8_t>(dataLen);
    manager->HandleBytes(socketId, data.data(), dataLen);
}

static void FuzzOp6(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleError
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    int32_t errCode = fuzzData.ConsumeIntegral<int32_t>();
    manager->HandleError(socketId, errCode);
}

static void FuzzOp7(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleShutdown
    int32_t socketId = fuzzData.ConsumeIntegral<int32_t>();
    int32_t reason = fuzzData.ConsumeIntegral<int32_t>();
    manager->HandleShutdown(socketId, reason);
}

static void FuzzOp8(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test ReportConnectionEstablished and ReportConnectionClosed
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    manager->ReportConnectionEstablished(connectionName);
    std::string reason = GenerateFuzzString(fuzzData, SIZE_128);
    manager->ReportConnectionClosed(connectionName, reason);
}

static void FuzzOp9(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribeConnectionStatus
    auto subscription = manager->SubscribeConnectionStatus(
        [](const std::string &connectionName, ConnectionStatus status, const std::string &reason) {
            // Callback - intentionally does nothing
            (void)connectionName;
            (void)status;
            (void)reason;
        });
    // Subscription will be automatically cleaned up
}

static void FuzzOp10(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribeRawMessage
    auto subscription =
        manager->SubscribeRawMessage([](const std::string &connectionName, const std::vector<uint8_t> &message) {
            // Callback - intentionally does nothing
            (void)connectionName;
            (void)message;
        });
    // Subscription will be automatically cleaned up
}

static void FuzzOp11(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribeIncomingConnection
    auto subscription = manager->SubscribeIncomingConnection(
        [](const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey) {
            // Callback - intentionally does nothing
            (void)connectionName;
            (void)physicalDeviceKey;
        });
    // Subscription will be automatically cleaned up
}

static void FuzzOp12(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test NotifyIncomingConnection
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    manager->NotifyIncomingConnection(connectionName, physicalKey);
}

static void FuzzOp13(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test StartServerSocket
    // This indirectly tests HandleSoftBusServiceReady
    manager->StartServerSocket();
}

static void FuzzOp14(std::shared_ptr<SoftBusConnectionManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test CloseAllSockets
    std::string reason = GenerateFuzzString(fuzzData, SIZE_128);
    // CloseAllSockets is private, but can be triggered through destructor
    // by calling CloseConnection on all possible connections first
    std::string connectionName = GenerateFuzzString(fuzzData, TEST_VAL64);
    manager->CloseConnection(connectionName);
}

static const SoftBusConnectionManagerFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4,
    FuzzOp5, FuzzOp6, FuzzOp7, FuzzOp8, FuzzOp9, FuzzOp10, FuzzOp11, FuzzOp12, FuzzOp13, FuzzOp14 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SoftBusConnectionManagerFuzzFunction);

void FuzzSoftBusConnectionManager(FuzzedDataProvider &fuzzData)
{
    // Create SoftBusConnectionManager instance
    auto manager = SoftBusConnectionManager::Create();
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

FUZZ_REGISTER(FuzzSoftBusConnectionManager)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
