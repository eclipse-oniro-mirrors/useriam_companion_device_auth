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

#ifndef COMPANION_DEVICE_AUTH_MOCK_GUARD_H
#define COMPANION_DEVICE_AUTH_MOCK_GUARD_H

#include <memory>

// Include all mock headers to provide complete type definitions
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

// RAII-style guard for managing all unittest mocks
class MockGuard {
public:
    MockGuard();
    ~MockGuard();

    // Prevent copying
    MockGuard(const MockGuard &) = delete;
    MockGuard &operator=(const MockGuard &) = delete;

    // AdapterManager mock access methods

    MockTimeKeeper &GetTimeKeeper();
    MockUserAuthAdapter &GetUserAuthAdapter();
    MockIdmAdapter &GetIdmAdapter();
    MockDriverManagerAdapter &GetDriverManagerAdapter();
    MockSAManagerAdapter &GetSaManagerAdapter();
    MockSystemParamManager &GetSystemParamManager();
    MockUserIdManager &GetUserIdManager();

    // SingletonManager mock access methods

    MockCrossDeviceCommManager &GetCrossDeviceCommManager();
    MockSecurityAgent &GetSecurityAgent();
    MockCompanionManager &GetCompanionManager();
    MockHostBindingManager &GetHostBindingManager();
    MockMiscManager &GetMiscManager();
    MockRequestManager &GetRequestManager();
    MockRequestFactory &GetRequestFactory();

private:
    // Helper methods for mock initialization
    void CreateMocks();
    void SetupDefaultBehaviors();
    void SetupMiscManagerDefaults();
    void SetupUserIdManagerDefaults();
    void SetupCrossDeviceCommManagerDefaults();
    void SetupCompanionManagerDefaults();
    void SetupRequestManagerDefaults();
    void SetupRequestFactoryDefaults();
    void SetupHostBindingManagerDefaults();
    void SetupSecurityAgentDefaults();

    // AdapterManager mock instances
    std::shared_ptr<MockTimeKeeper> timeKeeper_;
    std::shared_ptr<MockUserAuthAdapter> userAuthAdapter_;
    std::shared_ptr<MockIdmAdapter> idmAdapter_;
    std::shared_ptr<MockDriverManagerAdapter> driverManagerAdapter_;
    std::shared_ptr<MockSAManagerAdapter> saManagerAdapter_;
    std::shared_ptr<MockSystemParamManager> systemParamManager_;
    std::shared_ptr<MockUserIdManager> userIdManager_;

    // SingletonManager mock instances
    std::shared_ptr<MockCrossDeviceCommManager> crossDeviceCommManager_;
    std::shared_ptr<MockSecurityAgent> securityAgent_;
    std::shared_ptr<MockCompanionManager> companionManager_;
    std::shared_ptr<MockHostBindingManager> hostBindingManager_;
    std::shared_ptr<MockMiscManager> miscManager_;
    std::shared_ptr<MockRequestManager> requestManager_;
    std::shared_ptr<MockRequestFactory> requestFactory_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_MOCK_GUARD_H
