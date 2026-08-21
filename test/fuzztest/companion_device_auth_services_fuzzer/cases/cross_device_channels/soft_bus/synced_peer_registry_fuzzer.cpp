/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
#include "service_common.h"
#include "synced_peer_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using SyncedPeerRegistryFuzzFunction = void (*)(SyncedPeerRegistry &registry, FuzzedDataProvider &fuzzData);

// The registry private methods and members are reachable via the fuzzer's
// -Dprivate=public build flag, the same mechanism the unit tests use.
static PhysicalDeviceKey GenerateFuzzPhysicalDeviceKey(FuzzedDataProvider &fuzzData)
{
    PhysicalDeviceKey key;
    key.idType = GenerateFuzzDeviceIdType(fuzzData);
    key.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    return key;
}

// Feed raw fuzz bytes through the event decode path — Attributes parsing on
// attacker-controlled input.
static void FuzzOpFeedFuzzedEventData(SyncedPeerRegistry &registry, FuzzedDataProvider &fuzzData)
{
    EventData data =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    registry.HandlePeerSynced(data);
}

// Record a fuzzed physical key — drives LRU insertion and eviction.
static void FuzzOpRecordPeer(SyncedPeerRegistry &registry, FuzzedDataProvider &fuzzData)
{
    registry.RecordPeerSync(GenerateFuzzPhysicalDeviceKey(fuzzData));
}

// Query a fuzzed key — drives TTL compare and steady-time underflow paths.
static void FuzzOpQueryPeer(SyncedPeerRegistry &registry, FuzzedDataProvider &fuzzData)
{
    (void)registry.IsRecentlySynced(GenerateFuzzPhysicalDeviceKey(fuzzData));
}

// Re-Start — idempotency / re-subscribe stress.
static void FuzzOpStart(SyncedPeerRegistry &registry, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)registry.Start();
}

static const SyncedPeerRegistryFuzzFunction g_fuzzFuncs[] = {
    FuzzOpFeedFuzzedEventData,
    FuzzOpRecordPeer,
    FuzzOpQueryPeer,
    FuzzOpStart,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(SyncedPeerRegistryFuzzFunction);

void FuzzSyncedPeerRegistry(FuzzedDataProvider &fuzzData)
{
    SyncedPeerRegistry registry;
    (void)registry.Start();

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](registry, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](registry, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzSyncedPeerRegistry)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
