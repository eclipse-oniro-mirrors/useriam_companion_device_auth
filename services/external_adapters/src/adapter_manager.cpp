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

#include "adapter_manager.h"

#include <cstdlib>

#include "device_manager_adapter_impl.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "access_token_kit_adapter_impl.h"
#include "driver_manager_adapter_impl.h"
#include "sa_manager_adapter_impl.h"
#include "soft_bus_adapter_impl.h"
#include "user_auth_adapter_impl.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002510
#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

AdapterManager &AdapterManager::GetInstance()
{
    static AdapterManager instance;
    return instance;
}

bool AdapterManager::CreateAndRegisterAllAdapters()
{
    IAM_LOGI("Starting to create and register all adapters");

    auto saManagerAdapter = std::make_shared<SaManagerAdapterImpl>();
    ENSURE_OR_RETURN_VAL(saManagerAdapter != nullptr, false);
    SetSaManagerAdapter(saManagerAdapter);

    auto deviceManagerAdapter = DeviceManagerAdapterImpl::Create();
    ENSURE_OR_RETURN_VAL(deviceManagerAdapter != nullptr, false);
    SetDeviceManagerAdapter(deviceManagerAdapter);

    auto softBusAdapter = std::make_shared<SoftBusAdapterImpl>();
    ENSURE_OR_RETURN_VAL(softBusAdapter != nullptr, false);
    SetSoftBusAdapter(softBusAdapter);

    auto userAuthAdapter = std::make_shared<UserAuthAdapterImpl>();
    ENSURE_OR_RETURN_VAL(userAuthAdapter != nullptr, false);
    SetUserAuthAdapter(userAuthAdapter);

    auto driverManagerAdapter = std::make_shared<DriverManagerAdapterImpl>();
    ENSURE_OR_RETURN_VAL(driverManagerAdapter != nullptr, false);
    SetDriverManagerAdapter(driverManagerAdapter);

    auto accessTokenKitAdapter = std::make_shared<AccessTokenKitAdapterImpl>();
    ENSURE_OR_RETURN_VAL(accessTokenKitAdapter != nullptr, false);
    SetAccessTokenKitAdapter(accessTokenKitAdapter);

    IAM_LOGI("All adapters created and registered successfully");
    return true;
}

IDeviceManagerAdapter &AdapterManager::GetDeviceManagerAdapter()
{
    if (deviceManagerAdapter_ == nullptr) {
        IAM_LOGE("DeviceManager adapter is not initialized");
        AbortIfAdapterUninitialized("DeviceManager");
    }
    return *deviceManagerAdapter_;
}

void AdapterManager::SetDeviceManagerAdapter(std::shared_ptr<IDeviceManagerAdapter> adapter)
{
    deviceManagerAdapter_ = adapter;
}

ISoftBusAdapter &AdapterManager::GetSoftBusAdapter()
{
    if (softBusAdapter_ == nullptr) {
        IAM_LOGE("SoftBus adapter is not initialized");
        AbortIfAdapterUninitialized("SoftBus");
    }
    return *softBusAdapter_;
}

void AdapterManager::SetSoftBusAdapter(std::shared_ptr<ISoftBusAdapter> adapter)
{
    softBusAdapter_ = adapter;
}

IAccessTokenKitAdapter &AdapterManager::GetAccessTokenKitAdapter()
{
    if (accessTokenKitAdapter_ == nullptr) {
        IAM_LOGE("AccessTokenKit adapter is not initialized");
        AbortIfAdapterUninitialized("AccessTokenKit");
    }
    return *accessTokenKitAdapter_;
}

void AdapterManager::SetAccessTokenKitAdapter(std::shared_ptr<IAccessTokenKitAdapter> adapter)
{
    accessTokenKitAdapter_ = adapter;
}

IUserAuthAdapter &AdapterManager::GetUserAuthAdapter()
{
    if (userAuthAdapter_ == nullptr) {
        IAM_LOGE("UserAuth adapter is not initialized");
        AbortIfAdapterUninitialized("UserAuth");
    }
    return *userAuthAdapter_;
}

void AdapterManager::SetUserAuthAdapter(std::shared_ptr<IUserAuthAdapter> adapter)
{
    userAuthAdapter_ = adapter;
}

IDriverManagerAdapter &AdapterManager::GetDriverManagerAdapter()
{
    if (driverManagerAdapter_ == nullptr) {
        IAM_LOGE("DriverManager adapter is not initialized");
        AbortIfAdapterUninitialized("DriverManager");
    }
    return *driverManagerAdapter_;
}

void AdapterManager::SetDriverManagerAdapter(std::shared_ptr<IDriverManagerAdapter> adapter)
{
    driverManagerAdapter_ = adapter;
}

ISaManagerAdapter &AdapterManager::GetSaManagerAdapter()
{
    if (saManagerAdapter_ == nullptr) {
        IAM_LOGE("SaManager adapter is not initialized");
        AbortIfAdapterUninitialized("SaManager");
    }
    return *saManagerAdapter_;
}

void AdapterManager::SetSaManagerAdapter(std::shared_ptr<ISaManagerAdapter> adapter)
{
    saManagerAdapter_ = adapter;
}

void AdapterManager::AbortIfAdapterUninitialized(const char *adapterName)
{
    IAM_LOGF("%{public}s adapter is not initialized, abort", adapterName);
    std::abort();
}

#ifdef ENABLE_TEST
void AdapterManager::Reset()
{
    deviceManagerAdapter_ = nullptr;
    softBusAdapter_ = nullptr;
    accessTokenKitAdapter_ = nullptr;
    userAuthAdapter_ = nullptr;
    driverManagerAdapter_ = nullptr;
    saManagerAdapter_ = nullptr;
}
#endif

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
