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

#include <gmock/gmock.h>

#include "adapter_manager.h"
#include "relative_timer.h"
#include "service_common.h"
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

using namespace testing;

MockGuard::MockGuard()
{
    SingletonManager::GetInstance().Reset();
    AdapterManager::GetInstance().Reset();
    CreateMocks();
    SetupDefaultBehaviors();
}

void MockGuard::CreateMocks()
{
    // AdapterManager mocks
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

    // SingletonManager mocks
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

void MockGuard::SetupDefaultBehaviors()
{
    SetupMiscManagerDefaults();
    SetupUserIdManagerDefaults();
    SetupCrossDeviceCommManagerDefaults();
    SetupCompanionManagerDefaults();
    SetupRequestManagerDefaults();
    SetupRequestFactoryDefaults();
    SetupHostBindingManagerDefaults();
    SetupSecurityAgentDefaults();
}

void MockGuard::SetupMiscManagerDefaults()
{
    ON_CALL(*miscManager_, GetNextGlobalId()).WillByDefault(Return(1));
}

void MockGuard::SetupUserIdManagerDefaults()
{
    ON_CALL(*userIdManager_, GetActiveUserId()).WillByDefault(Return(0));
    ON_CALL(*userIdManager_, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return std::make_unique<Subscription>([]() {});
    }));
}

void MockGuard::SetupCrossDeviceCommManagerDefaults()
{
    ON_CALL(*crossDeviceCommManager_, Start()).WillByDefault(Return(true));
    ON_CALL(*crossDeviceCommManager_, IsAuthMaintainActive()).WillByDefault(Return(false));
    ON_CALL(*crossDeviceCommManager_, SubscribeIsAuthMaintainActive(_))
        .WillByDefault(Invoke([](std::function<void(bool)> &&) { return std::make_unique<Subscription>([]() {}); }));
    ON_CALL(*crossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(LocalDeviceProfile {}));
    ON_CALL(*crossDeviceCommManager_, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(*crossDeviceCommManager_, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(*crossDeviceCommManager_, SubscribeAllDeviceStatus(_)).WillByDefault(Invoke([](OnDeviceStatusChange &&) {
        return std::make_unique<Subscription>([]() {});
    }));
    ON_CALL(*crossDeviceCommManager_, SetSubscribeMode(_)).WillByDefault(Return());
    ON_CALL(*crossDeviceCommManager_, GetManageSubscribeTime()).WillByDefault(Return(std::nullopt));
    ON_CALL(*crossDeviceCommManager_, SubscribeDeviceStatus(_, _))
        .WillByDefault(
            Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));
    ON_CALL(*crossDeviceCommManager_, OpenConnection(_, _)).WillByDefault(Return(false));
    ON_CALL(*crossDeviceCommManager_, CloseConnection(_)).WillByDefault(Return());
    ON_CALL(*crossDeviceCommManager_, IsConnectionOpen(_)).WillByDefault(Return(false));
    ON_CALL(*crossDeviceCommManager_, GetConnectionStatus(_)).WillByDefault(Return(ConnectionStatus::DISCONNECTED));
    ON_CALL(*crossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(*crossDeviceCommManager_, SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke(
            [](const std::string &, OnConnectionStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));
    ON_CALL(*crossDeviceCommManager_, SubscribeIncomingConnection(_, _))
        .WillByDefault(Invoke([](MessageType, OnMessage &&) { return std::make_unique<Subscription>([]() {}); }));
    ON_CALL(*crossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(false));
    ON_CALL(*crossDeviceCommManager_, SubscribeMessage(_, _, _))
        .WillByDefault(Invoke(
            [](const std::string &, MessageType, OnMessage &&) { return std::make_unique<Subscription>([]() {}); }));
    ON_CALL(*crossDeviceCommManager_, CheckOperationIntent(_, _, _)).WillByDefault(Return(false));
    ON_CALL(*crossDeviceCommManager_, HostGetSecureProtocolId(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(*crossDeviceCommManager_, CompanionGetSecureProtocolId()).WillByDefault(Return(SecureProtocolId::DEFAULT));
}

void MockGuard::SetupCompanionManagerDefaults()
{
    ON_CALL(*companionManager_, GetCompanionStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(*companionManager_, GetCompanionStatus(_, _)).WillByDefault(Return(std::nullopt));
    ON_CALL(*companionManager_, GetAllCompanionStatus()).WillByDefault(Return(std::vector<CompanionStatus> {}));
    ON_CALL(*companionManager_, SubscribeCompanionDeviceStatusChange(_))
        .WillByDefault(
            Invoke([](OnCompanionDeviceStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));
    ON_CALL(*companionManager_, UnsubscribeCompanionDeviceStatusChange(_)).WillByDefault(Return());
    ON_CALL(*companionManager_, BeginAddCompanion(_, _)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*companionManager_, EndAddCompanion(_, _)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*companionManager_, RemoveCompanion(_)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*companionManager_, UpdateCompanionStatus(_, _, _)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*companionManager_, UpdateCompanionEnabledBusinessIds(_, _))
        .WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*companionManager_, SetCompanionTokenAtl(_, _)).WillByDefault(Return(true));
    ON_CALL(*companionManager_, UpdateToken(_, _, _)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*companionManager_, HandleCompanionCheckFail(_)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*companionManager_, StartIssueTokenRequests(_, _)).WillByDefault(Return());
    ON_CALL(*companionManager_, NotifyCompanionStatusChange()).WillByDefault(Return());
    ON_CALL(*companionManager_, HandleRemoveHostBindingComplete(_)).WillByDefault(Return());
}

void MockGuard::SetupRequestManagerDefaults()
{
    ON_CALL(*requestManager_, Start(_)).WillByDefault(Return(true));
}

void MockGuard::SetupRequestFactoryDefaults()
{
    ON_CALL(*requestFactory_, CreateCompanionRevokeTokenRequest(_, _)).WillByDefault(Return(nullptr));
    ON_CALL(*requestFactory_, CreateHostSyncDeviceStatusRequest(_, _, _, _)).WillByDefault(Return(nullptr));
}

void MockGuard::SetupHostBindingManagerDefaults()
{
    ON_CALL(*hostBindingManager_, GetHostBindingStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(*hostBindingManager_, GetHostBindingStatus(_, _)).WillByDefault(Return(std::nullopt));
    ON_CALL(*hostBindingManager_, BeginAddHostBinding(_, _, _, _, _)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*hostBindingManager_, EndAddHostBinding(_, _, _)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*hostBindingManager_, RemoveHostBinding(_, _)).WillByDefault(Return(ResultCode::GENERAL_ERROR));
    ON_CALL(*hostBindingManager_, SetHostBindingTokenValid(_, _)).WillByDefault(Return(true));
    ON_CALL(*hostBindingManager_, StartObtainTokenRequests(_, _)).WillByDefault(Return());
    ON_CALL(*hostBindingManager_, RevokeTokens(_)).WillByDefault(Return());
}

void MockGuard::SetupSecurityAgentDefaults()
{
    ON_CALL(*securityAgent_, Init()).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, SetActiveUser(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostGetExecutorInfo(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostOnRegisterFinish(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostGetPersistedCompanionStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostBeginCompanionCheck(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostEndCompanionCheck(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostCancelCompanionCheck(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, CompanionProcessCheck(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostGetInitKeyNegotiationRequest(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostBeginAddCompanion(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
}

MockGuard::~MockGuard()
{
    // Execute all pending tasks BEFORE clearing mocks
    // This ensures that any pending requests can properly access singleton managers
    // and prevents stale callbacks from accessing released singletons
    // Use EnsureAllTaskExecuted to handle nested async tasks
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    RelativeTimer::GetInstance().EnsureAllTaskExecuted();

    // Reset infrastructure FIRST to clear all manager pointers
    // This must happen before we try to set them to nullptr
    SingletonManager::GetInstance().Reset();
    AdapterManager::GetInstance().Reset();

    // Now it's safe to clear AdapterManager mocks (these don't have nullptr checks)
    AdapterManager::GetInstance().SetTimeKeeper(nullptr);
    AdapterManager::GetInstance().SetUserAuthAdapter(nullptr);
    AdapterManager::GetInstance().SetIdmAdapter(nullptr);
    AdapterManager::GetInstance().SetDriverManagerAdapter(nullptr);
    AdapterManager::GetInstance().SetSaManagerAdapter(nullptr);
    AdapterManager::GetInstance().SetSystemParamManager(nullptr);
    AdapterManager::GetInstance().SetUserIdManager(nullptr);

    // SingletonManager mocks are already reset, so no need to set to nullptr
    // The Reset() call above already cleared all shared_ptr references
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
