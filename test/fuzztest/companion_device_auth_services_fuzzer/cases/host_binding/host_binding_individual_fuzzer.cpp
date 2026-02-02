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
#include "host_binding.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HostBindingFuzzFunction = void (*)(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData);

static void FuzzGetBindingId(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (binding) {
        auto bindingId = binding->GetBindingId();
        (void)bindingId;
    }
}

static void FuzzGetCompanionUserId(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (binding) {
        auto userId = binding->GetCompanionUserId();
        (void)userId;
    }
}

static void FuzzGetHostDeviceKey(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (binding) {
        auto deviceKey = binding->GetHostDeviceKey();
        (void)deviceKey;
    }
}

static void FuzzGetStatus(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (binding) {
        auto status = binding->GetStatus();
        (void)status;
    }
}

static void FuzzGetDescription(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (binding) {
        auto description = binding->GetDescription();
        (void)description;
    }
}

static void FuzzSetTokenValid(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    if (binding) {
        bool isTokenValid = fuzzData.ConsumeBool();
        binding->SetTokenValid(isTokenValid);
    }
}

static void FuzzHandleDeviceStatusChanged(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    if (binding) {
        uint8_t statusCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
        std::vector<DeviceStatus> deviceStatusList;
        for (uint8_t i = 0; i < statusCount; ++i) {
            deviceStatusList.push_back(GenerateFuzzDeviceStatus(fuzzData));
        }
        binding->HandleDeviceStatusChanged(deviceStatusList);
    }
}

static void FuzzHandleHostDeviceStatusUpdate(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    if (binding) {
        DeviceStatus deviceStatus = GenerateFuzzDeviceStatus(fuzzData);
        binding->HandleHostDeviceStatusUpdate(deviceStatus);
    }
}

static void FuzzHandleHostDeviceOffline(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    if (binding) {
        binding->HandleHostDeviceOffline();
    }
}

static void FuzzHandleAuthMaintainActiveChanged(std::shared_ptr<HostBinding> &binding, FuzzedDataProvider &fuzzData)
{
    if (binding) {
        bool isActive = fuzzData.ConsumeBool();
        binding->HandleAuthMaintainActiveChanged(isActive);
    }
}

static const HostBindingFuzzFunction g_fuzzFuncs[] = {
    FuzzGetBindingId,
    FuzzGetCompanionUserId,
    FuzzGetHostDeviceKey,
    FuzzGetStatus,
    FuzzGetDescription,
    FuzzSetTokenValid,
    FuzzHandleDeviceStatusChanged,
    FuzzHandleHostDeviceStatusUpdate,
    FuzzHandleHostDeviceOffline,
    FuzzHandleAuthMaintainActiveChanged,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostBindingFuzzFunction);

void FuzzHostBindingIndividual(FuzzedDataProvider &fuzzData)
{
    PersistedHostBindingStatus persistedStatus = GenerateFuzzPersistedHostBindingStatus(fuzzData);
    auto binding = HostBinding::Create(persistedStatus);
    if (!binding) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](binding, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](binding, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzHostBindingIndividual)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
