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

#include "device_status_entry.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr int32_t INT32_10 = 10;
constexpr int32_t INT32_50 = 50;
constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_1000 = 1000;
constexpr int32_t INT32_99999 = 99999;
} // namespace

using DeviceStatusEntryFuzzFunction = void (*)(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData);

static void FuzzOnUserIdChange(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (entry) {
        entry->OnUserIdChange();
    }
}

static void FuzzBuildDeviceKey(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    if (entry) {
        auto key = entry->BuildDeviceKey(userId);
        (void)key;
    }
}

static void FuzzBuildDeviceStatus(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    if (entry) {
        auto status = entry->BuildDeviceStatus(userId);
        (void)status;
    }
}

static void FuzzIsSameDevice(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    if (entry) {
        PhysicalDeviceKey key;
        key.idType = GenerateFuzzDeviceIdType(fuzzData);
        key.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
        ChannelId channelId = GenerateFuzzChannelId(fuzzData);
        bool isSame = entry->IsSameDevice(key, channelId);
        (void)isSame;
    }
}

// Test BuildDeviceKey with boundary userId values
static void FuzzBuildDeviceKeyBoundary(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    if (entry) {
        std::vector<UserId> testUserIds = { 0, INT32_100, INT32_99999, INT32_MAX, fuzzData.ConsumeIntegral<UserId>() };
        for (auto userId : testUserIds) {
            auto key = entry->BuildDeviceKey(userId);
            (void)key;
        }
    }
}

// Test BuildDeviceStatus with boundary userId values
static void FuzzBuildDeviceStatusBoundary(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    if (entry) {
        std::vector<UserId> testUserIds = { 0, INT32_50, INT32_1000, INT32_MAX, fuzzData.ConsumeIntegral<UserId>() };
        for (auto userId : testUserIds) {
            auto status = entry->BuildDeviceStatus(userId);
            (void)status;
        }
    }
}

// Test OnUserIdChange multiple times
static void FuzzOnUserIdChangeRepeated(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    int num = INT32_10;
    if (entry) {
        for (int i = 0; i < num; ++i) {
            entry->OnUserIdChange();
        }
    }
}

// Test IsSameDevice with various channel IDs
static void FuzzIsSameDeviceChannelBoundary(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    if (entry) {
        PhysicalDeviceKey key;
        key.idType = GenerateFuzzDeviceIdType(fuzzData);
        key.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);

        // Test with different channel IDs
        std::vector<ChannelId> testChannelIds = { static_cast<ChannelId>(0), static_cast<ChannelId>(-1),
            GenerateFuzzChannelId(fuzzData) };

        for (auto channelId : testChannelIds) {
            bool isSame = entry->IsSameDevice(key, channelId);
            (void)isSame;
        }
    }
}

// Test IsSameDevice with empty deviceId
static void FuzzIsSameDeviceEmptyId(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    if (entry) {
        PhysicalDeviceKey key;
        key.idType = GenerateFuzzDeviceIdType(fuzzData);
        key.deviceId = ""; // Empty device ID
        ChannelId channelId = GenerateFuzzChannelId(fuzzData);
        bool isSame = entry->IsSameDevice(key, channelId);
        (void)isSame;
    }
}

// Test IsSameDevice with very long deviceId
static void FuzzIsSameDeviceLongId(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    if (entry) {
        PhysicalDeviceKey key;
        key.idType = GenerateFuzzDeviceIdType(fuzzData);
        // Generate a very long device ID (TEST_VAL1024 characters)
        key.deviceId = GenerateFuzzString(fuzzData, TEST_VAL1024);
        ChannelId channelId = GenerateFuzzChannelId(fuzzData);
        bool isSame = entry->IsSameDevice(key, channelId);
        (void)isSame;
    }
}

// Test BuildDeviceKey and BuildDeviceStatus combination
static void FuzzBuildKeyThenStatus(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    if (entry) {
        auto key = entry->BuildDeviceKey(userId);
        auto status = entry->BuildDeviceStatus(userId);
        (void)key;
        (void)status;
    }
}

// Test IsSameDevice with all deviceIdType values
static void FuzzIsSameDeviceAllTypes(std::shared_ptr<DeviceStatusEntry> &entry, FuzzedDataProvider &fuzzData)
{
    if (entry) {
        std::vector<DeviceIdType> allTypes = { GenerateFuzzDeviceIdType(fuzzData), DeviceIdType::UNIFIED_DEVICE_ID };

        for (auto idType : allTypes) {
            PhysicalDeviceKey key;
            key.idType = idType;
            key.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
            ChannelId channelId = GenerateFuzzChannelId(fuzzData);
            bool isSame = entry->IsSameDevice(key, channelId);
            (void)isSame;
        }
    }
}

static const DeviceStatusEntryFuzzFunction g_fuzzFuncs[] = {
    FuzzOnUserIdChange,
    FuzzBuildDeviceKey,
    FuzzBuildDeviceStatus,
    FuzzIsSameDevice,
    FuzzBuildDeviceKeyBoundary,
    FuzzBuildDeviceStatusBoundary,
    FuzzOnUserIdChangeRepeated,
    FuzzIsSameDeviceChannelBoundary,
    FuzzIsSameDeviceEmptyId,
    FuzzIsSameDeviceLongId,
    FuzzBuildKeyThenStatus,
    FuzzIsSameDeviceAllTypes,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(DeviceStatusEntryFuzzFunction);

void FuzzDeviceStatusEntry(FuzzedDataProvider &fuzzData)
{
    PhysicalDeviceStatus physicalStatus;
    physicalStatus.physicalDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalStatus.physicalDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    physicalStatus.channelId = GenerateFuzzChannelId(fuzzData);
    physicalStatus.networkId = GenerateFuzzString(fuzzData, TEST_VAL64);
    physicalStatus.deviceModelInfo = GenerateFuzzString(fuzzData, TEST_VAL64);
    physicalStatus.deviceName = GenerateFuzzString(fuzzData, TEST_VAL64);
    physicalStatus.isAuthMaintainActive = fuzzData.ConsumeBool();

    auto entry = std::make_shared<DeviceStatusEntry>(physicalStatus, []() {});
    if (!entry) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](entry, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(DeviceStatusEntry)

} // namespace UserIam
} // namespace OHOS
