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
#include "sa_manager_adapter.h"
#include "user_auth_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class AdapterManager : public NoCopyable {
public:
    static AdapterManager &GetInstance();

    bool CreateAndRegisterAllAdapters();

    IUserAuthAdapter &GetUserAuthAdapter();
    void SetUserAuthAdapter(std::shared_ptr<IUserAuthAdapter> adapter);

    IAccessTokenKitAdapter &GetAccessTokenKitAdapter();
    void SetAccessTokenKitAdapter(std::shared_ptr<IAccessTokenKitAdapter> adapter);

    IDriverManagerAdapter &GetDriverManagerAdapter();
    void SetDriverManagerAdapter(std::shared_ptr<IDriverManagerAdapter> adapter);

    ISaManagerAdapter &GetSaManagerAdapter();
    void SetSaManagerAdapter(std::shared_ptr<ISaManagerAdapter> adapter);

#ifdef ENABLE_TEST
    void Reset();
#endif

private:
    AdapterManager() = default;
    ~AdapterManager() = default;

    void AbortIfAdapterUninitialized(const char *adapterName);

    std::shared_ptr<IUserAuthAdapter> userAuthAdapter_;
    std::shared_ptr<IAccessTokenKitAdapter> accessTokenKitAdapter_;
    std::shared_ptr<IDriverManagerAdapter> driverManagerAdapter_;
    std::shared_ptr<ISaManagerAdapter> saManagerAdapter_;
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

inline ISaManagerAdapter &GetSaManagerAdapter()
{
    return AdapterManager::GetInstance().GetSaManagerAdapter();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ADAPTER_MANAGER_H
