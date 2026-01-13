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

#include "iam_check.h"
#include "iam_logger.h"

#include "common_defines.h"

#ifdef HAS_USER_AUTH_FRAMEWORK
#include "driver_manager_adapter_impl.h"
#include "user_auth_adapter_impl.h"
#endif

#include "access_token_kit_adapter_impl.h"
#include "sa_manager_adapter_impl.h"

#include "driver_manager_adapter.h"
#include "user_auth_adapter.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002510
#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class UserAuthAdapterDummy : public IUserAuthAdapter {
public:
    UserAuthAdapterDummy() = default;
    ~UserAuthAdapterDummy() override = default;

    uint64_t BeginDelegateAuth(uint32_t userId, const std::vector<uint8_t> &challenge, uint32_t authTrustLevel,
        AuthResultCallback callback) override
    {
        IAM_LOGE("UserAuth framework is not supported, BeginDelegateAuth will fail");
        callback(ResultCode::GENERAL_ERROR, {});
        return 0;
    }

    int32_t CancelAuthentication(uint64_t contextId) override
    {
        IAM_LOGE("UserAuth framework is not supported, CancelAuthentication will fail");
        return ResultCode::GENERAL_ERROR;
    }
};

class DriverManagerAdapterDummy : public IDriverManagerAdapter {
public:
    DriverManagerAdapterDummy() = default;
    ~DriverManagerAdapterDummy() override = default;

    bool Start(std::shared_ptr<CompanionDeviceAuthDriver> driver) override
    {
        IAM_LOGE("DriverManager framework is not supported, Start will fail");
        return false;
    }
};

AdapterManager &AdapterManager::GetInstance()
{
    static AdapterManager instance;
    return instance;
}

bool AdapterManager::CreateAndRegisterAllAdapters()
{
    IAM_LOGI("Starting to create and register general adapters");

    auto saManagerAdapter = std::make_shared<SaManagerAdapterImpl>();
    ENSURE_OR_RETURN_VAL(saManagerAdapter != nullptr, false);
    SetSaManagerAdapter(saManagerAdapter);

    auto accessTokenKitAdapter = std::make_shared<AccessTokenKitAdapterImpl>();
    ENSURE_OR_RETURN_VAL(accessTokenKitAdapter != nullptr, false);
    SetAccessTokenKitAdapter(accessTokenKitAdapter);

#ifdef HAS_USER_AUTH_FRAMEWORK
    // UserAuthAdapter
    auto userAuthAdapter = std::make_shared<UserAuthAdapterImpl>();
    ENSURE_OR_RETURN_VAL(userAuthAdapter != nullptr, false);
    SetUserAuthAdapter(userAuthAdapter);

    // DriverManagerAdapter
    auto driverManagerAdapter = std::make_shared<DriverManagerAdapterImpl>();
    ENSURE_OR_RETURN_VAL(driverManagerAdapter != nullptr, false);
    SetDriverManagerAdapter(driverManagerAdapter);
#else
    // Dummy implementations
    auto userAuthAdapter = std::make_shared<UserAuthAdapterDummy>();
    SetUserAuthAdapter(userAuthAdapter);

    auto driverManagerAdapter = std::make_shared<DriverManagerAdapterDummy>();
    SetDriverManagerAdapter(driverManagerAdapter);
#endif

    IAM_LOGI("General adapters created and registered successfully");
    return true;
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
    userAuthAdapter_ = nullptr;
    accessTokenKitAdapter_ = nullptr;
    driverManagerAdapter_ = nullptr;
    saManagerAdapter_ = nullptr;
}
#endif

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
