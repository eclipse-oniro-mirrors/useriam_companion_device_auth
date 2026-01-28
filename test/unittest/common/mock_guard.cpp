/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mock_guard.h"

#include "adapter_manager.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

// Include all mock headers
#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_driver_manager_adapter.h"
#include "mock_host_binding_manager.h"
#include "mock_idm_adapter.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_sa_manager_adapter.h"
#include "mock_security_agent.h"
#include "mock_system_param_manager.h"
#include "mock_time_keeper.h"
#include "mock_user_auth_adapter.h"
#include "mock_user_id_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

MockGuard::MockGuard()
{
    // Reset infrastructure
    SingletonManager::GetInstance().Reset();

    // Create and register AdapterManager mocks
    timeKeeper_ = std::make_shared<MockTimeKeeper>();
    AdapterManager::GetInstance().SetTimeKeeper(timeKeeper_);

    userAuthAdapter_ = std::make_shared<MockUserAuthAdapter>();
    AdapterManager::GetInstance().SetUserAuthAdapter(userAuthAdapter_);

    idmAdapter_ = std::make_shared<MockIdmAdapter>();
    AdapterManager::GetInstance().SetIdmAdapter(idmAdapter_);

    driverManagerAdapter_ = std::make_shared<MockDriverManagerAdapter>();
    AdapterManager::GetInstance().SetDriverManagerAdapter(driverManagerAdapter_);

    saManagerAdapter_ = std::make_shared<MockSAManagerAdapter>();
    AdapterManager::GetInstance().SetSaManagerAdapter(saManagerAdapter_);

    systemParamManager_ = std::make_shared<MockSystemParamManager>();
    AdapterManager::GetInstance().SetSystemParamManager(systemParamManager_);

    userIdManager_ = std::make_shared<MockUserIdManager>();
    AdapterManager::GetInstance().SetUserIdManager(userIdManager_);

    // Create and register SingletonManager mocks
    crossDeviceCommManager_ = std::make_shared<MockCrossDeviceCommManager>();
    SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommManager_);

    securityAgent_ = std::make_shared<MockSecurityAgent>();
    SingletonManager::GetInstance().SetSecurityAgent(securityAgent_);

    companionManager_ = std::make_shared<MockCompanionManager>();
    SingletonManager::GetInstance().SetCompanionManager(companionManager_);

    hostBindingManager_ = std::make_shared<MockHostBindingManager>();
    SingletonManager::GetInstance().SetHostBindingManager(hostBindingManager_);

    miscManager_ = std::make_shared<MockMiscManager>();
    SingletonManager::GetInstance().SetMiscManager(miscManager_);

    requestManager_ = std::make_shared<MockRequestManager>();
    SingletonManager::GetInstance().SetRequestManager(requestManager_);

    requestFactory_ = std::make_shared<MockRequestFactory>();
    SingletonManager::GetInstance().SetRequestFactory(requestFactory_);
}

MockGuard::~MockGuard()
{
    // Clear AdapterManager mocks
    AdapterManager::GetInstance().SetTimeKeeper(nullptr);
    AdapterManager::GetInstance().SetUserAuthAdapter(nullptr);
    AdapterManager::GetInstance().SetIdmAdapter(nullptr);
    AdapterManager::GetInstance().SetDriverManagerAdapter(nullptr);
    AdapterManager::GetInstance().SetSaManagerAdapter(nullptr);
    AdapterManager::GetInstance().SetSystemParamManager(nullptr);
    AdapterManager::GetInstance().SetUserIdManager(nullptr);

    // Clear SingletonManager mocks
    SingletonManager::GetInstance().SetCrossDeviceCommManager(nullptr);
    SingletonManager::GetInstance().SetSecurityAgent(nullptr);
    SingletonManager::GetInstance().SetCompanionManager(nullptr);
    SingletonManager::GetInstance().SetHostBindingManager(nullptr);
    SingletonManager::GetInstance().SetMiscManager(nullptr);
    SingletonManager::GetInstance().SetRequestManager(nullptr);
    SingletonManager::GetInstance().SetRequestFactory(nullptr);

    // Reset infrastructure
    AdapterManager::GetInstance().Reset();
    SingletonManager::GetInstance().Reset();
    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().ExecuteAll();
}

// AdapterManager mock access methods

MockTimeKeeper &MockGuard::GetTimeKeeper()
{
    return *timeKeeper_;
}

MockUserAuthAdapter &MockGuard::GetUserAuthAdapter()
{
    return *userAuthAdapter_;
}

MockIdmAdapter &MockGuard::GetIdmAdapter()
{
    return *idmAdapter_;
}

MockDriverManagerAdapter &MockGuard::GetDriverManagerAdapter()
{
    return *driverManagerAdapter_;
}

MockSAManagerAdapter &MockGuard::GetSaManagerAdapter()
{
    return *saManagerAdapter_;
}

MockSystemParamManager &MockGuard::GetSystemParamManager()
{
    return *systemParamManager_;
}

MockUserIdManager &MockGuard::GetUserIdManager()
{
    return *userIdManager_;
}

// SingletonManager mock access methods

MockCrossDeviceCommManager &MockGuard::GetCrossDeviceCommManager()
{
    return *crossDeviceCommManager_;
}

MockSecurityAgent &MockGuard::GetSecurityAgent()
{
    return *securityAgent_;
}

MockCompanionManager &MockGuard::GetCompanionManager()
{
    return *companionManager_;
}

MockHostBindingManager &MockGuard::GetHostBindingManager()
{
    return *hostBindingManager_;
}

MockMiscManager &MockGuard::GetMiscManager()
{
    return *miscManager_;
}

MockRequestManager &MockGuard::GetRequestManager()
{
    return *requestManager_;
}

MockRequestFactory &MockGuard::GetRequestFactory()
{
    return *requestFactory_;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
