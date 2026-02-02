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

#include "companion.h"
#include "companion_manager_impl.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using CompanionFuzzFunction = void (*)(std::shared_ptr<Companion> &companion, FuzzedDataProvider &fuzzData);

static void FuzzSetEnabledBusinessIds(std::shared_ptr<Companion> &companion, FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_BUSINESS_IDS_COUNT);
    std::vector<BusinessId> businessIds;
    for (uint8_t j = 0; j < count; ++j) {
        businessIds.push_back(static_cast<BusinessId>(fuzzData.ConsumeIntegral<int32_t>()));
    }
    companion->SetEnabledBusinessIds(businessIds);
}

static void FuzzSetCompanionValid(std::shared_ptr<Companion> &companion, FuzzedDataProvider &fuzzData)
{
    bool isValid = fuzzData.ConsumeBool();
    companion->SetCompanionValid(isValid);
}

static void FuzzSetCompanionTokenAtl(std::shared_ptr<Companion> &companion, FuzzedDataProvider &fuzzData)
{
    if (fuzzData.ConsumeBool()) {
        Atl tokenAtl = fuzzData.ConsumeIntegral<Atl>();
        companion->SetCompanionTokenAtl(tokenAtl);
    } else {
        companion->SetCompanionTokenAtl(std::nullopt);
    }
}

static void FuzzSetDeviceNames(std::shared_ptr<Companion> &companion, FuzzedDataProvider &fuzzData)
{
    std::string deviceName = GenerateFuzzString(fuzzData, TEST_VAL64);
    std::string deviceUserName = GenerateFuzzString(fuzzData, TEST_VAL64);
    companion->SetDeviceNames(deviceName, deviceUserName);
}

static void FuzzNotifySubscribers(std::shared_ptr<Companion> &companion, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    companion->NotifySubscribers();
}

static void FuzzGetters(std::shared_ptr<Companion> &companion, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)companion->GetTemplateId();
    (void)companion->GetHostUserId();
    (void)companion->GetCompanionDeviceKey();
    (void)companion->GetStatus();
    (void)companion->GetDescription();
}

static void FuzzDeviceStatusHandling(std::shared_ptr<Companion> &companion, FuzzedDataProvider &fuzzData)
{
    (void)companion;
    std::vector<DeviceStatus> statusList;
    uint8_t statusCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
    for (uint8_t j = 0; j < statusCount; ++j) {
        DeviceStatus status;
        status.deviceKey = GenerateFuzzDeviceKey(fuzzData);
        status.channelId = GenerateFuzzChannelId(fuzzData);
        status.deviceModelInfo = GenerateFuzzString(fuzzData, TEST_VAL64);
        status.deviceUserName = GenerateFuzzString(fuzzData, TEST_VAL64);
        status.deviceName = GenerateFuzzString(fuzzData, TEST_VAL64);
        status.protocolId = GenerateFuzzProtocolId(fuzzData);
        status.secureProtocolId = GenerateFuzzSecureProtocolId(fuzzData);
        status.isOnline = fuzzData.ConsumeBool();
        status.isAuthMaintainActive = fuzzData.ConsumeBool();
        statusList.push_back(status);
    }
}

static const CompanionFuzzFunction g_fuzzFuncs[] = {
    FuzzSetEnabledBusinessIds,
    FuzzSetCompanionValid,
    FuzzSetCompanionTokenAtl,
    FuzzSetDeviceNames,
    FuzzNotifySubscribers,
    FuzzGetters,
    FuzzDeviceStatusHandling,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CompanionFuzzFunction);

void FuzzCompanion(FuzzedDataProvider &fuzzData)
{
    PersistedCompanionStatus persistedStatus;
    persistedStatus.templateId = fuzzData.ConsumeIntegral<uint64_t>();
    persistedStatus.hostUserId = fuzzData.ConsumeIntegral<int32_t>();
    persistedStatus.companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    persistedStatus.isValid = fuzzData.ConsumeBool();

    auto mockManager = std::make_shared<CompanionManagerImpl>();
    auto managerWeakPtr = std::weak_ptr<CompanionManagerImpl>(mockManager);

    auto companion = Companion::Create(persistedStatus, false, managerWeakPtr);
    if (!companion) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](companion, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](companion, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzCompanion)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
