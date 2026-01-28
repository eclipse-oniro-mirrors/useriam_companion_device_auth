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

#ifndef COMPANION_DEVICE_AUTH_ADAPTER_MANAGER_H
#define COMPANION_DEVICE_AUTH_ADAPTER_MANAGER_H

#include <memory>

#include "nocopyable.h"

// External adapters
#include "access_token_kit_adapter.h"
#include "driver_manager_adapter.h"
#include "event_manager_adapter.h"
#include "idm_adapter.h"
#include "sa_manager_adapter.h"
#include "security_command_adapter.h"
#include "user_auth_adapter.h"

#include "system_param_manager.h"
#include "time_keeper.h"
#include "user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class AdapterManager : public NoCopyable {
public:
    static AdapterManager &GetInstance();

    IUserAuthAdapter &GetUserAuthAdapter();
    void SetUserAuthAdapter(std::shared_ptr<IUserAuthAdapter> adapter);

    IAccessTokenKitAdapter &GetAccessTokenKitAdapter();
    void SetAccessTokenKitAdapter(std::shared_ptr<IAccessTokenKitAdapter> adapter);

    IDriverManagerAdapter &GetDriverManagerAdapter();
    void SetDriverManagerAdapter(std::shared_ptr<IDriverManagerAdapter> adapter);

    IIdmAdapter &GetIdmAdapter();
    void SetIdmAdapter(std::shared_ptr<IIdmAdapter> adapter);

    ISaManagerAdapter &GetSaManagerAdapter();
    void SetSaManagerAdapter(std::shared_ptr<ISaManagerAdapter> adapter);

    ISecurityCommandAdapter &GetSecurityCommandAdapter();
    void SetSecurityCommandAdapter(std::shared_ptr<ISecurityCommandAdapter> adapter);

    IEventManagerAdapter &GetEventManagerAdapter();
    void SetEventManagerAdapter(std::shared_ptr<IEventManagerAdapter> adapter);

    ITimeKeeper &GetTimeKeeper();
    void SetTimeKeeper(std::shared_ptr<ITimeKeeper> adapter);

    ISystemParamManager &GetSystemParamManager();
    void SetSystemParamManager(std::shared_ptr<ISystemParamManager> adapter);

    IUserIdManager &GetUserIdManager();
    void SetUserIdManager(std::shared_ptr<IUserIdManager> adapter);

#ifdef ENABLE_TEST
    void Reset();
#endif // ENABLE_TEST

private:
    AdapterManager() = default;
    ~AdapterManager() = default;

    void AbortIfAdapterUninitialized(const char *adapterName);

    std::shared_ptr<IUserAuthAdapter> userAuthAdapter_;
    std::shared_ptr<IAccessTokenKitAdapter> accessTokenKitAdapter_;
    std::shared_ptr<IDriverManagerAdapter> driverManagerAdapter_;
    std::shared_ptr<IIdmAdapter> idmAdapter_;
    std::shared_ptr<ISaManagerAdapter> saManagerAdapter_;
    std::shared_ptr<ISecurityCommandAdapter> securityCommandAdapter_;
    std::shared_ptr<IEventManagerAdapter> eventManagerAdapter_;
    std::shared_ptr<ITimeKeeper> timeKeeperAdapter_;
    std::shared_ptr<ISystemParamManager> systemParamManager_;
    std::shared_ptr<IUserIdManager> userIdManager_;
};

inline IUserAuthAdapter &GetUserAuthAdapter()
{
    return AdapterManager::GetInstance().GetUserAuthAdapter();
}

inline IAccessTokenKitAdapter &GetAccessTokenKitAdapter()
{
    return AdapterManager::GetInstance().GetAccessTokenKitAdapter();
}

inline IDriverManagerAdapter &GetDriverManagerAdapter()
{
    return AdapterManager::GetInstance().GetDriverManagerAdapter();
}

inline IIdmAdapter &GetIdmAdapter()
{
    return AdapterManager::GetInstance().GetIdmAdapter();
}

inline ISaManagerAdapter &GetSaManagerAdapter()
{
    return AdapterManager::GetInstance().GetSaManagerAdapter();
}

inline ISecurityCommandAdapter &GetSecurityCommandAdapter()
{
    return AdapterManager::GetInstance().GetSecurityCommandAdapter();
}

inline IEventManagerAdapter &GetEventManagerAdapter()
{
    return AdapterManager::GetInstance().GetEventManagerAdapter();
}

inline ITimeKeeper &GetTimeKeeper()
{
    return AdapterManager::GetInstance().GetTimeKeeper();
}

inline ISystemParamManager &GetSystemParamManager()
{
    return AdapterManager::GetInstance().GetSystemParamManager();
}

inline IUserIdManager &GetUserIdManager()
{
    return AdapterManager::GetInstance().GetUserIdManager();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ADAPTER_MANAGER_H
