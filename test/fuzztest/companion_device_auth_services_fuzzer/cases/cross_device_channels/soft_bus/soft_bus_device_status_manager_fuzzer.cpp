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

#include "device_manager.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "soft_bus_device_status_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SoftBusDeviceStatusManagerFuzzFunction = void (*)(std::shared_ptr<SoftBusDeviceStatusManager> &,
    FuzzedDataProvider &);

static void FuzzOp0(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Start
    manager->Start();
}

static void FuzzOp1(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetAuthMaintainActive
    (void)manager->GetAuthMaintainActive();
}

static void FuzzOp2(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetPhysicalDeviceStatus
    PhysicalDeviceKey key;
    uint32_t testVal64 = 64;
    key.idType = GenerateFuzzDeviceIdType(fuzzData);
    key.deviceId = GenerateFuzzString(fuzzData, testVal64);
    (void)manager->GetPhysicalDeviceStatus(key);
}

static void FuzzOp3(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetAllPhysicalDevices
    (void)manager->GetAllPhysicalDevices();
}

static void FuzzOp4(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetLocalPhysicalDeviceKey
    auto localKey = manager->GetLocalPhysicalDeviceKey();
    (void)localKey;
}

static void FuzzOp5(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test RefreshDeviceStatus
    // This indirectly tests QueryTrustedDevices and ConvertToPhysicalDevices
    manager->RefreshDeviceStatus();
}

static void FuzzOp6(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleLocalIsAuthMaintainActiveChange
    // This indirectly tests NotifyAuthMaintainActiveChange
    bool isActive = fuzzData.ConsumeBool();
    manager->HandleLocalIsAuthMaintainActiveChange(isActive);
}

static void FuzzOp7(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribePhysicalDeviceStatus
    auto subscription =
        manager->SubscribePhysicalDeviceStatus([](const std::vector<PhysicalDeviceStatus> &deviceStatus) {
            // Callback - intentionally does nothing
            (void)deviceStatus;
        });
    // Subscription will be automatically cleaned up
}

static void FuzzOp8(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SubscribeAuthMaintainActive
    auto subscription = manager->SubscribeAuthMaintainActive([](bool isActive) {
        // Callback - intentionally does nothing
        (void)isActive;
    });
    // Subscription will be automatically cleaned up
}

static void FuzzOp9(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test IsDeviceTypeIdSupport
    auto deviceTypeId = static_cast<DistributedHardware::DmDeviceType>(fuzzData.ConsumeIntegral<uint32_t>());
    (void)manager->IsDeviceTypeIdSupport(deviceTypeId);
}

static void FuzzOp10(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test InitDeviceManager
    (void)manager->InitDeviceManager();
}

static void FuzzOp11(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test RegisterDeviceStatusCallback
    (void)manager->RegisterDeviceStatusCallback();
}

static void FuzzOp12(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test NotifyDeviceStatusChange
    manager->NotifyDeviceStatusChange();
}

static void FuzzOp13(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleDeviceManagerServiceReady
    manager->HandleDeviceManagerServiceReady();
}

static void FuzzOp14(std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test HandleDeviceManagerServiceUnavailable
    manager->HandleDeviceManagerServiceUnavailable();
}

static const SoftBusDeviceStatusManagerFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3, FuzzOp4,
    FuzzOp5, FuzzOp6, FuzzOp7, FuzzOp8, FuzzOp9, FuzzOp10, FuzzOp11, FuzzOp12, FuzzOp13, FuzzOp14 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SoftBusDeviceStatusManagerFuzzFunction);

void FuzzSoftBusDeviceStatusManager(FuzzedDataProvider &fuzzData)
{
    // Create SoftBusDeviceStatusManager instance
    auto manager = SoftBusDeviceStatusManager::Create();
    if (!manager) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](manager, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(SoftBusDeviceStatusManager)

} // namespace UserIam
} // namespace OHOS
