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
#include "idm_adapter_impl.h"
#include "user_auth_adapter_impl.h"
#endif

#include "access_token_kit_adapter_impl.h"
#include "event_manager_adapter_impl.h"
#include "sa_manager_adapter_impl.h"
#include "security_command_adapter_impl.h"
#include "system_param_manager_impl.h"
#include "time_keeper_impl.h"

#include "driver_manager_adapter.h"
#include "idm_adapter.h"
#include "subscription.h"
#include "user_auth_adapter.h"

#undef LOG_TAG
#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

AdapterManager &AdapterManager::GetInstance()
{
    static AdapterManager instance;
    return instance;
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

IIdmAdapter &AdapterManager::GetIdmAdapter()
{
    if (idmAdapter_ == nullptr) {
        IAM_LOGE("IDM adapter is not initialized");
        AbortIfAdapterUninitialized("IDM");
    }
    return *idmAdapter_;
}

void AdapterManager::SetIdmAdapter(std::shared_ptr<IIdmAdapter> adapter)
{
    idmAdapter_ = adapter;
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

ISecurityCommandAdapter &AdapterManager::GetSecurityCommandAdapter()
{
    if (securityCommandAdapter_ == nullptr) {
        IAM_LOGE("SecurityCommand adapter is not initialized");
        AbortIfAdapterUninitialized("SecurityCommand");
    }
    return *securityCommandAdapter_;
}

void AdapterManager::SetSecurityCommandAdapter(std::shared_ptr<ISecurityCommandAdapter> adapter)
{
    securityCommandAdapter_ = adapter;
}

IEventManagerAdapter &AdapterManager::GetEventManagerAdapter()
{
    if (eventManagerAdapter_ == nullptr) {
        IAM_LOGE("EventManager adapter is not initialized");
        AbortIfAdapterUninitialized("EventManager");
    }
    return *eventManagerAdapter_;
}

void AdapterManager::SetEventManagerAdapter(std::shared_ptr<IEventManagerAdapter> adapter)
{
    eventManagerAdapter_ = adapter;
}

ITimeKeeper &AdapterManager::GetTimeKeeper()
{
    if (timeKeeperAdapter_ == nullptr) {
        IAM_LOGE("TimeKeeper adapter is not initialized");
        AbortIfAdapterUninitialized("TimeKeeper");
    }
    return *timeKeeperAdapter_;
}

void AdapterManager::SetTimeKeeper(std::shared_ptr<ITimeKeeper> adapter)
{
    timeKeeperAdapter_ = adapter;
}

ISystemParamManager &AdapterManager::GetSystemParamManager()
{
    if (systemParamManager_ == nullptr) {
        IAM_LOGE("SystemParamManager is not initialized");
        AbortIfAdapterUninitialized("SystemParamManager");
    }
    return *systemParamManager_;
}

void AdapterManager::SetSystemParamManager(std::shared_ptr<ISystemParamManager> adapter)
{
    systemParamManager_ = adapter;
}

IUserIdManager &AdapterManager::GetUserIdManager()
{
    if (userIdManager_ == nullptr) {
        IAM_LOGE("UserIdManager is not initialized");
        AbortIfAdapterUninitialized("UserIdManager");
    }
    return *userIdManager_;
}

void AdapterManager::SetUserIdManager(std::shared_ptr<IUserIdManager> adapter)
{
    userIdManager_ = adapter;
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
    idmAdapter_ = nullptr;
    saManagerAdapter_ = nullptr;
    securityCommandAdapter_ = nullptr;
    eventManagerAdapter_ = nullptr;
    timeKeeperAdapter_ = nullptr;
    systemParamManager_ = nullptr;
    userIdManager_ = nullptr;
}
#endif // ENABLE_TEST

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
