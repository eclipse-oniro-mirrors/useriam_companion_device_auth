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

#include "channel_manager.h"
#include "connection_manager.h"
#include "device_status_manager.h"
#include "fuzz_constants.h"
#include "fuzz_cross_device_channel.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "local_device_status_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr uint8_t UINT8_2 = 2;
}

using DeviceStatusManagerFuzzFunction = void (*)(std::shared_ptr<DeviceStatusManager> &mgr,
    FuzzedDataProvider &fuzzData);

static void FuzzGetDeviceStatus(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto status = mgr->GetDeviceStatus(deviceKey);
    (void)status;
}

static void FuzzGetAllDeviceStatus(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto allStatus = mgr->GetAllDeviceStatus();
    (void)allStatus;
}

static void FuzzSubscribeDeviceStatus(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto callback = [](const std::vector<DeviceStatus> &statusList) { (void)statusList; };
    auto subscription = mgr->SubscribeDeviceStatus(deviceKey, std::move(callback));
    (void)subscription;
}

static void FuzzSetSubscribeMode(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    uint8_t modeValue = fuzzData.ConsumeIntegralInRange<uint8_t>(0, UINT8_2);
    SubscribeMode mode = static_cast<SubscribeMode>(modeValue);
    mgr->SetSubscribeMode(mode);
}

static void FuzzGetManageSubscribeTime(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto time = mgr->GetManageSubscribeTime();
    (void)time;
}

static void FuzzSubscribeAllDeviceStatus(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto callback = [](const std::vector<DeviceStatus> &statusList) { (void)statusList; };
    auto subscription = mgr->SubscribeDeviceStatus(std::move(callback));
    (void)subscription;
}

static void FuzzGetChannelIdByDeviceKey(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto channelId = mgr->GetChannelIdByDeviceKey(deviceKey);
    (void)channelId;
}

static void FuzzInitialize(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    mgr->Initialize();
}

static void FuzzHandleSyncResult(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    int32_t resultCode = fuzzData.ConsumeIntegral<int32_t>();
    SyncDeviceStatus syncStatus;
    syncStatus.deviceKey = deviceKey;
    syncStatus.protocolIdList.push_back(static_cast<ProtocolId>(fuzzData.ConsumeIntegral<uint8_t>()));
    syncStatus.capabilityList.push_back(static_cast<Capability>(fuzzData.ConsumeIntegral<uint8_t>()));
    syncStatus.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint8_t>());
    syncStatus.deviceUserName = GenerateFuzzString(fuzzData, TEST_VAL64);
    mgr->HandleSyncResult(deviceKey, resultCode, syncStatus);
}

static void FuzzTriggerDeviceSync(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    mgr->TriggerDeviceSync(physicalKey);
}

static void FuzzStartPeriodicSync(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    mgr->StartPeriodicSync();
}

static void FuzzStopPeriodicSync(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    mgr->StopPeriodicSync();
}

static void FuzzUnsubscribeDeviceStatus(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    SubscribeId subscriptionId = fuzzData.ConsumeIntegral<SubscribeId>();
    bool result = mgr->UnsubscribeDeviceStatus(subscriptionId);
    (void)result;
}

static void FuzzNegotiateProtocol(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    uint8_t protocolCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_PROTOCOLS_COUNT);
    std::vector<ProtocolId> protocols;
    for (uint8_t i = 0; i < protocolCount; ++i) {
        protocols.push_back(static_cast<ProtocolId>(fuzzData.ConsumeIntegral<uint8_t>()));
    }
    auto protocolId = mgr->NegotiateProtocol(protocols);
    (void)protocolId;
}

static void FuzzNegotiateCapabilities(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    uint8_t capCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_CAPABILITIES_COUNT);
    std::vector<Capability> capabilities;
    for (uint8_t i = 0; i < capCount; ++i) {
        capabilities.push_back(static_cast<Capability>(fuzzData.ConsumeIntegral<uint8_t>()));
    }
    auto caps = mgr->NegotiateCapabilities(capabilities);
    (void)caps;
}

static void FuzzShouldMonitorDevice(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    PhysicalDeviceKey physicalKey;
    physicalKey.idType = GenerateFuzzDeviceIdType(fuzzData);
    physicalKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
    bool shouldMonitor = mgr->ShouldMonitorDevice(physicalKey);
    (void)shouldMonitor;
}

static void FuzzHandleUserIdChange(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    mgr->HandleUserIdChange(userId);
}

static void FuzzHandleChannelDeviceStatusChange(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    ChannelId channelId = GenerateFuzzChannelId(fuzzData);
    uint8_t statusCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
    std::vector<PhysicalDeviceStatus> statusList;
    for (uint8_t i = 0; i < statusCount; ++i) {
        PhysicalDeviceStatus status;
        status.physicalDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData);
        status.physicalDeviceKey.deviceId = GenerateFuzzString(fuzzData, TEST_VAL64);
        status.channelId = GenerateFuzzChannelId(fuzzData);
        status.deviceName = GenerateFuzzString(fuzzData, TEST_VAL64);
        status.deviceModelInfo = GenerateFuzzString(fuzzData, TEST_VAL64);
        statusList.push_back(status);
    }
    mgr->HandleChannelDeviceStatusChange(channelId, statusList);
}

static void FuzzRefreshDeviceList(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    bool resync = fuzzData.ConsumeBool();
    mgr->RefreshDeviceList(resync);
}

static void FuzzCollectFilteredDevices(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto devices = mgr->CollectFilteredDevices();
    (void)devices;
}

static void FuzzRemoveObsoleteDevices(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::map<PhysicalDeviceKey, PhysicalDeviceStatus> filteredDevicesMap;
    bool result = mgr->RemoveObsoleteDevices(filteredDevicesMap);
    (void)result;
}

static void FuzzAddOrUpdateDevices(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    std::map<PhysicalDeviceKey, PhysicalDeviceStatus> filteredDevicesMap;
    bool resync = fuzzData.ConsumeBool();
    bool result = mgr->AddOrUpdateDevices(filteredDevicesMap, resync);
    (void)result;
}

static void FuzzNotifySubscribers(std::shared_ptr<DeviceStatusManager> &mgr, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    mgr->NotifySubscribers();
}

static const DeviceStatusManagerFuzzFunction g_fuzzFuncs[] = {
    FuzzGetDeviceStatus,
    FuzzGetAllDeviceStatus,
    FuzzSubscribeDeviceStatus,
    FuzzSetSubscribeMode,
    FuzzGetManageSubscribeTime,
    FuzzSubscribeAllDeviceStatus,
    FuzzGetChannelIdByDeviceKey,
    FuzzInitialize,
    FuzzHandleSyncResult,
    FuzzTriggerDeviceSync,
    FuzzStartPeriodicSync,
    FuzzStopPeriodicSync,
    FuzzUnsubscribeDeviceStatus,
    FuzzNegotiateProtocol,
    FuzzNegotiateCapabilities,
    FuzzShouldMonitorDevice,
    FuzzHandleUserIdChange,
    FuzzHandleChannelDeviceStatusChange,
    FuzzRefreshDeviceList,
    FuzzCollectFilteredDevices,
    FuzzRemoveObsoleteDevices,
    FuzzAddOrUpdateDevices,
    FuzzNotifySubscribers,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(DeviceStatusManagerFuzzFunction);

void FuzzDeviceStatusManager(FuzzedDataProvider &fuzzData)
{
    // Create a fuzz channel so LocalDeviceStatusManager::Init() succeeds
    auto fuzzChannel = std::make_shared<FuzzCrossDeviceChannel>(fuzzData);
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels;
    channels.push_back(fuzzChannel);

    auto channelMgr = std::make_shared<ChannelManager>(channels);
    if (!channelMgr) {
        return;
    }

    auto localDeviceStatusMgr = LocalDeviceStatusManager::Create(channelMgr);
    if (!localDeviceStatusMgr) {
        return;
    }

    auto connectionMgr = ConnectionManager::Create(channelMgr, localDeviceStatusMgr);
    if (!connectionMgr) {
        return;
    }

    auto mgr = DeviceStatusManager::Create(connectionMgr, channelMgr, localDeviceStatusMgr);
    if (!mgr) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](mgr, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](mgr, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzDeviceStatusManager)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
