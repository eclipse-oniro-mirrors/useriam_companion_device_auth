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

using HostBindingFuzzFunction = void (*)(std::shared_ptr<HostBinding> &hostBinding, FuzzedDataProvider &fuzzData);

static void FuzzSetTokenValid(std::shared_ptr<HostBinding> &hostBinding, FuzzedDataProvider &fuzzData)
{
    bool isTokenValid = fuzzData.ConsumeBool();
    hostBinding->SetTokenValid(isTokenValid);
}

static void FuzzHandleDeviceStatusChanged(std::shared_ptr<HostBinding> &hostBinding, FuzzedDataProvider &fuzzData)
{
    uint8_t statusCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
    std::vector<DeviceStatus> statusList = GenerateFuzzDeviceStatusList(fuzzData, statusCount);
    hostBinding->HandleDeviceStatusChanged(statusList);
}

static void FuzzHandleHostDeviceStatusUpdate(std::shared_ptr<HostBinding> &hostBinding, FuzzedDataProvider &fuzzData)
{
    DeviceStatus deviceStatus = GenerateFuzzDeviceStatus(fuzzData);
    hostBinding->HandleHostDeviceStatusUpdate(deviceStatus);
}

static void FuzzHandleHostDeviceOffline(std::shared_ptr<HostBinding> &hostBinding, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    hostBinding->HandleHostDeviceOffline();
}

static void FuzzHandleAuthMaintainActiveChanged(std::shared_ptr<HostBinding> &hostBinding, FuzzedDataProvider &fuzzData)
{
    bool isActive = fuzzData.ConsumeBool();
    hostBinding->HandleAuthMaintainActiveChanged(isActive);
}

static void FuzzGetAllMethods(std::shared_ptr<HostBinding> &hostBinding, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)hostBinding->GetBindingId();
    (void)hostBinding->GetCompanionUserId();
    (void)hostBinding->GetHostDeviceKey();
    (void)hostBinding->GetStatus();
    (void)hostBinding->GetDescription();
}

static const HostBindingFuzzFunction g_fuzzFuncs[] = {
    FuzzSetTokenValid,
    FuzzHandleDeviceStatusChanged,
    FuzzHandleHostDeviceStatusUpdate,
    FuzzHandleHostDeviceOffline,
    FuzzHandleAuthMaintainActiveChanged,
    FuzzGetAllMethods,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostBindingFuzzFunction);

void FuzzHostBinding(FuzzedDataProvider &fuzzData)
{
    PersistedHostBindingStatus persistedStatus = GenerateFuzzPersistedHostBindingStatus(fuzzData);

    auto hostBinding = HostBinding::Create(persistedStatus);
    if (!hostBinding) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](hostBinding, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(HostBinding)

} // namespace UserIam
} // namespace OHOS
