/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "device_resync_scheduler.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "service_common.h"
#include "soft_bus_device_status_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using DeviceResyncSchedulerFuzzFunction = void (*)(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData);

// physicalDeviceStatus_, scheduledResyncs_, and the scheduler private methods are reachable via
// the fuzzer's -Dprivate=public build flag, the same mechanism the unit tests use.
static PhysicalDeviceKey GenerateFuzzPhysicalDeviceKey(FuzzedDataProvider &fuzzData)
{
    PhysicalDeviceKey key;
    key.idType = GenerateFuzzDeviceIdType(fuzzData);
    key.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    return key;
}

// Push a fuzzed device into the manager's online set, then deliver the snapshot — drives the
// newly-online diff path (first delivery seeds prevOnline, later ones trigger resync).
static void FuzzOpBringDeviceOnline(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    if (scheduler == nullptr || manager == nullptr) {
        return;
    }
    PhysicalDeviceStatus status;
    status.physicalDeviceKey = GenerateFuzzPhysicalDeviceKey(fuzzData);
    manager->physicalDeviceStatus_.push_back(status);
    scheduler->OnPhysicalDeviceStatusChanged(manager->physicalDeviceStatus_);
}

// Drop one online device and deliver the snapshot — drives offline retry cancellation.
static void FuzzOpTakeDeviceOffline(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    if (scheduler == nullptr || manager == nullptr) {
        return;
    }
    auto &devices = manager->physicalDeviceStatus_;
    if (devices.empty()) {
        return;
    }
    uint8_t idx = fuzzData.ConsumeIntegralInRange<uint8_t>(0, static_cast<uint8_t>(devices.size() - 1));
    devices.erase(devices.begin() + idx);
    scheduler->OnPhysicalDeviceStatusChanged(manager->physicalDeviceStatus_);
}

// Redeliver the current snapshot unchanged — drives the no-new-devices path.
static void FuzzOpReplaySnapshot(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (scheduler == nullptr || manager == nullptr) {
        return;
    }
    scheduler->OnPhysicalDeviceStatusChanged(manager->physicalDeviceStatus_);
}

// External trigger for a single device — drives EnsureRetryEntry/ResetBackoff/DoResyncOneDevice
// (factory + RequestManager::Start), including coalescing when repeated for one key.
static void FuzzOpResyncOneDevice(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    if (scheduler == nullptr) {
        return;
    }
    PhysicalDeviceKey key = GenerateFuzzPhysicalDeviceKey(fuzzData);
    std::string reason = GenerateFuzzString(fuzzData, TEST_VAL64);
    scheduler->ResyncOneDevice(key, reason);
}

// Complete an in-flight resync for an existing entry — drives success-erase / failure-arm-retry /
// offline-skip / exhaustion. Half the time a stale request id is used to exercise the drop path.
static void FuzzOpCompleteResync(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    if (scheduler == nullptr) {
        return;
    }
    auto &entries = scheduler->scheduledResyncs_;
    if (entries.empty()) {
        return;
    }
    uint8_t idx = fuzzData.ConsumeIntegralInRange<uint8_t>(0, static_cast<uint8_t>(entries.size() - 1));
    auto it = entries.begin();
    std::advance(it, idx);
    uint64_t attemptId = fuzzData.ConsumeBool() ? it->second.inProgressAttemptId : fuzzData.ConsumeIntegral<uint64_t>();
    ResultCode result = GenerateFuzzResultCode(fuzzData);
    scheduler->HandleResyncComplete(it->first, attemptId, result);
}

// Fire the backoff retry for an existing entry — drives retry-fire-without-counter-reset.
static void FuzzOpFireRetryTimer(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    if (scheduler == nullptr) {
        return;
    }
    auto &entries = scheduler->scheduledResyncs_;
    if (entries.empty()) {
        return;
    }
    uint8_t idx = fuzzData.ConsumeIntegralInRange<uint8_t>(0, static_cast<uint8_t>(entries.size() - 1));
    auto it = entries.begin();
    std::advance(it, idx);
    scheduler->OnRetryTimerFired(it->first);
}

// Fan out a resync to every online device.
static void FuzzOpResyncAll(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)manager;
    if (scheduler == nullptr) {
        return;
    }
    std::string reason = GenerateFuzzString(fuzzData, TEST_VAL64);
    scheduler->ResyncAllPhysicalDevices(reason);
}

// Re-Start — idempotency / re-subscribe stress.
static void FuzzOpStart(std::shared_ptr<DeviceResyncScheduler> &scheduler,
    std::shared_ptr<SoftBusDeviceStatusManager> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)manager;
    if (scheduler == nullptr) {
        return;
    }
    (void)scheduler->Start();
}

static const DeviceResyncSchedulerFuzzFunction g_fuzzFuncs[] = {
    FuzzOpBringDeviceOnline,
    FuzzOpTakeDeviceOffline,
    FuzzOpReplaySnapshot,
    FuzzOpResyncOneDevice,
    FuzzOpCompleteResync,
    FuzzOpFireRetryTimer,
    FuzzOpResyncAll,
    FuzzOpStart,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(DeviceResyncSchedulerFuzzFunction);

void FuzzDeviceResyncScheduler(FuzzedDataProvider &fuzzData)
{
    auto manager = SoftBusDeviceStatusManager::Create();
    if (!manager) {
        return;
    }

    auto scheduler = DeviceResyncScheduler::Create(manager);
    if (!scheduler) {
        return;
    }
    (void)scheduler->Start();

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](scheduler, manager, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](scheduler, manager, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzDeviceResyncScheduler)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
