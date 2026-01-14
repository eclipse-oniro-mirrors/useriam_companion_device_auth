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

#include "soft_bus_adapter_manager.h"

#include <cstdlib>

#include "device_manager_adapter_impl.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "soft_bus_adapter_impl.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002510
#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

SoftBusAdapterManager &SoftBusAdapterManager::GetInstance()
{
    static SoftBusAdapterManager instance;
    return instance;
}

bool SoftBusAdapterManager::CreateAndRegisterAdapters()
{
    IAM_LOGI("Starting to create and register SoftBus adapters");

    // DeviceManagerAdapter
    auto deviceManagerAdapter = DeviceManagerAdapterImpl::Create();
    ENSURE_OR_RETURN_VAL(deviceManagerAdapter != nullptr, false);
    SetDeviceManagerAdapter(deviceManagerAdapter);

    // SoftBusAdapter
    auto softBusAdapter = std::make_shared<SoftBusAdapterImpl>();
    ENSURE_OR_RETURN_VAL(softBusAdapter != nullptr, false);
    SetSoftBusAdapter(softBusAdapter);

    IAM_LOGI("SoftBus adapters created and registered successfully");
    return true;
}

IDeviceManagerAdapter &SoftBusAdapterManager::GetDeviceManagerAdapter()
{
    if (deviceManagerAdapter_ == nullptr) {
        IAM_LOGE("DeviceManager adapter is not initialized");
        AbortIfAdapterUninitialized("DeviceManager");
    }
    return *deviceManagerAdapter_;
}

void SoftBusAdapterManager::SetDeviceManagerAdapter(std::shared_ptr<IDeviceManagerAdapter> adapter)
{
    deviceManagerAdapter_ = adapter;
}

ISoftBusAdapter &SoftBusAdapterManager::GetSoftBusAdapter()
{
    if (softBusAdapter_ == nullptr) {
        IAM_LOGE("SoftBus adapter is not initialized");
        AbortIfAdapterUninitialized("SoftBus");
    }
    return *softBusAdapter_;
}

void SoftBusAdapterManager::SetSoftBusAdapter(std::shared_ptr<ISoftBusAdapter> adapter)
{
    softBusAdapter_ = adapter;
}

void SoftBusAdapterManager::AbortIfAdapterUninitialized(const char *adapterName)
{
    IAM_LOGF("%{public}s adapter is not initialized, abort", adapterName);
    std::abort();
}

#ifdef ENABLE_TEST
void SoftBusAdapterManager::Reset()
{
    deviceManagerAdapter_ = nullptr;
    softBusAdapter_ = nullptr;
}
#endif

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
