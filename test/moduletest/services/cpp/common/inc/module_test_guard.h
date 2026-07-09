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

#ifndef COMPANION_DEVICE_AUTH_TEST_MODULETEST_SERVICES_MODULE_TEST_GUARD_H
#define COMPANION_DEVICE_AUTH_TEST_MODULETEST_SERVICES_MODULE_TEST_GUARD_H

#include <memory>

#include "module_test_helpers.h"
#include "refbase.h"

// Base class — production init pipeline
#include "base_service_initializer.h"

// Global accessor functions for real singletons registered by BaseServiceInitializer
#include "singleton_manager.h"

// Fakes (stateful + callback-aware test doubles)
#include "fake_channel.h"
#include "fake_driver_manager_adapter.h"
#include "fake_idm_adapter.h"
#include "fake_misc_manager.h"
#include "fake_sa_manager_adapter.h"
#include "fake_system_param_manager.h"
#include "fake_user_id_manager.h"

// Mocks (gmock for return value control)
#include "mock_event_manager_adapter.h"
#include "mock_security_agent.h"
#include "mock_system_settings_manager.h"
#include "mock_time_keeper.h"
#include "mock_user_auth_adapter.h"

// Service core (for direct API access without IPC)
#include "base_service_core.h"

// Framework executor interface

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// TestServiceInitializer overrides virtual Initialize*() methods from BaseServiceInitializer
// to inject Fake/Mock adapters. The init order and wiring remain identical to production
// (BASIC_INIT_TABLE + InitializeDependentSteps).
//
// Methods NOT overridden (RequestManager, RequestFactory, IncomingMessageHandlerRegistry,
// CrossDeviceCommManager, CompanionManager, HostBindingManager, RegisterHandlers,
// StartCrossDeviceCommManager, InitializeFwkComm) use the real production implementations.
class TestServiceInitializer : public BaseServiceInitializer {
public:
    static std::shared_ptr<TestServiceInitializer> Create();
    ~TestServiceInitializer() override = default;

    // ---- Fake accessors (stateful, callback-aware) ----
    FakeChannel &GetChannel();
    MockTimeKeeper &GetTimeKeeper();
    FakeUserIdManager &GetUserIdManager();
    FakeSystemParamManager &GetSystemParamManager();
    FakeMiscManager &GetMiscManager();
    FakeIdmAdapter &GetIdmAdapter();
    FakeSaManagerAdapter &GetSaManagerAdapter();
    FakeDriverManagerAdapter &GetDriverManagerAdapter();

    // ---- Mock accessors (gmock) ----
    MockUserAuthAdapter &GetUserAuthAdapter();
    MockEventManagerAdapter &GetEventManagerAdapter();
    MockSecurityAgent &GetSecurityAgent();
    MockSystemSettingsManager &GetSystemSettingsManager();

    // Internal pointer accessors for VerifyAndClear
    std::shared_ptr<MockSecurityAgent> GetSecurityAgentPtr() const;
    std::shared_ptr<MockUserAuthAdapter> GetUserAuthAdapterPtr() const;
    std::shared_ptr<MockEventManagerAdapter> GetEventManagerAdapterPtr() const;

protected:
    // ---- AdapterManager injections (override base) ----
    bool InitializeTimeKeeper() override;
    bool InitializeEventManagerAdapter() override;
    bool InitializeSaManagerAdapter() override;
    bool InitializeSecurityCommandAdapter() override;
    bool InitializeSystemParamManager() override;
    bool InitializeUserIdManager() override;
    bool InitializeSystemSettingsManager() override;
    bool InitializeUserAuthFramework() override;

    // ---- SingletonManager injections (override base) ----
    bool InitializeMiscManager() override;
    bool InitializeSecurityAgent() override;

    // ---- Channel injection (FakeChannel instead of SoftBus) ----
    bool InitializeChannels() override;

private:
    explicit TestServiceInitializer(std::shared_ptr<SubscriptionManager> subscriptionManager);
    void SetupSecurityAgentDefaults();

    // AdapterManager adapters
    std::shared_ptr<MockTimeKeeper> timeKeeper_;
    std::shared_ptr<MockUserAuthAdapter> userAuthAdapter_;
    std::shared_ptr<FakeIdmAdapter> idmAdapter_;
    std::shared_ptr<FakeDriverManagerAdapter> driverManagerAdapter_;
    std::shared_ptr<FakeSaManagerAdapter> saManagerAdapter_;
    std::shared_ptr<FakeSystemParamManager> systemParamManager_;
    std::shared_ptr<FakeUserIdManager> userIdManager_;
    std::shared_ptr<MockSystemSettingsManager> systemSettingsManager_;
    std::shared_ptr<MockEventManagerAdapter> eventManagerAdapter_;

    // Singletons
    std::shared_ptr<MockSecurityAgent> securityAgent_;
    std::shared_ptr<FakeMiscManager> miscManager_;

    // Transport boundary
    std::shared_ptr<FakeChannel> channel_;
};

// ModuleTestGuard exercises the production OnStart() flow:
//   Reset → TestServiceInitializer::Create (19-step init with Fakes)
//   → CompanionDeviceAuthService::OnStart (creates BaseServiceCore, sets function-ready param)
//   → SetupDefaultValues (active user, time, mock defaults)
//
// Destruction: drain tasks → VerifyAndClear mocks → clear service → Reset
class ModuleTestGuard {
public:
    ModuleTestGuard();
    ~ModuleTestGuard();

    ModuleTestGuard(const ModuleTestGuard &) = delete;
    ModuleTestGuard &operator=(const ModuleTestGuard &) = delete;

    // Fake accessors
    FakeChannel &GetChannel();
    MockTimeKeeper &GetTimeKeeper();
    FakeUserIdManager &GetUserIdManager();
    FakeSystemParamManager &GetSystemParamManager();
    FakeMiscManager &GetMiscManager();
    FakeIdmAdapter &GetIdmAdapter();
    FakeSaManagerAdapter &GetSaManagerAdapter();
    FakeDriverManagerAdapter &GetDriverManagerAdapter();

    // Mock accessors
    MockUserAuthAdapter &GetUserAuthAdapter();
    MockEventManagerAdapter &GetEventManagerAdapter();
    MockSecurityAgent &GetSecurityAgent();
    MockSystemSettingsManager &GetSystemSettingsManager();

    // Core accessor (for E2E tests that need service-level APIs without IPC)
    BaseServiceCore &GetCore()
    {
        return *core_;
    }

    // Executor-like helpers: mimic production Executor.Enroll()/Authenticate() behavior
    // without requiring external Fwk interface dependencies.
    // These helpers follow the production pattern: wrap callback, build fwkMsg,
    // call Create*Request(), then Start(request).

    // Mimics Executor.Enroll() for AddCompanion flow
    bool Enroll(ScheduleId scheduleId, const std::vector<uint8_t> &extraInfo, TemplateId tokenId,
        const std::string &additionalInfo, FwkResultCallback &&callback);

    // Mimics Executor.Authenticate() for TokenAuth flow
    bool AuthenticateTokenAuth(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg, UserId userId,
        TemplateId templateId, uint32_t lockStateAuthType, FwkResultCallback &&callback);

    // Mimics Executor.Authenticate() for DelegateAuth flow
    bool AuthenticateDelegateAuth(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg, UserId userId,
        TemplateId templateId, uint32_t authIntent, FwkResultCallback &&callback);

    // IssueToken: uses CompanionManager.StartIssueTokenRequests() (production path)
    void StartIssueTokenRequests(const std::vector<TemplateId> &templateIds, uint32_t lockStateAuthType,
        const std::vector<uint8_t> &fwkUnlockMsg, FwkResultCallback &&callback);

    // RemoveHostBinding: uses CompanionManager.RemoveCompanion() (production path)
    ResultCode RemoveCompanion(TemplateId templateId, FwkResultCallback &&callback);

    // Setup helper: Online a companion device and register it (host-side setup).
    // Combines TestSimulateDeviceOnline + RegisterCompanionDirect.
    bool SetupCompanionDevice(UserId hostUser, const std::string &deviceId, TemplateId templateId);

    // Setup helper: Online a companion device (without registration).
    void SimulateDeviceOnline(const std::string &deviceId);

    // Setup helper: Register a companion already online.
    bool RegisterCompanion(UserId hostUser, const std::string &deviceId, TemplateId templateId);

    // Setup helper: Register a host binding (companion-side setup).
    // Combines the SecurityAgent mock expectation + RegisterHostBindingDirect.
    bool SetupHostBinding(UserId companionUserId, const std::string &hostDeviceId, BindingId bindingId = 1);

    // Setup helper: Register a companion via full E2E message flow.
    // Uses the complete Enroll -> message injection flow.
    // Returns true on success, false on failure.
    bool RegisterCompanionViaMessageFlow(UserId hostUserId, const DeviceKey &companionDeviceKey, TemplateId templateId,
        UserId companionUserId);

    // Setup helper: Register a companion directly (bypass message flow, for setup phase only).
    // Calls CompanionManager.EndAddCompanion directly to create a companion binding.
    bool RegisterCompanionDirect(UserId hostUserId, const DeviceKey &companionDeviceKey, TemplateId templateId,
        const std::vector<BusinessId> &enabledBusinessIds = {});

    // Setup helper: Register a host binding directly (for companion-side inbound handler tests).
    // Uses HostBindingManager.BeginAddHostBinding with SecurityAgent mock.
    bool RegisterHostBindingDirect(UserId companionUserId, const DeviceKey &hostDeviceKey, BindingId bindingId = 1);

    // ---- Message flow helpers (reduce test function line count) ----

    // Returns the last connection name, or empty string if none.
    std::string GetAnyConnectionName();

    // Capture outbound message on connection, verify msgType. Returns decoded info or nullopt.
    std::optional<RawMsgInfo> CaptureOutboundMessage(const std::string &connName, MessageType expectedType);

    // Build reply raw msg, clear sent, inject, drain.
    void InjectTypedReply(const std::string &connName, uint32_t seq, MessageType msgType,
        const Attributes &replyPayload);

    // Combined: capture outbound + inject reply. Returns captured msg info or nullopt.
    std::optional<RawMsgInfo> CaptureVerifyAndReply(const std::string &connName, MessageType expectedType,
        const Attributes &replyPayload);

    // Clear sent, inject incoming message, drain. For companion-side inbound tests.
    void InjectCompanionRequest(const std::string &connName, const std::vector<uint8_t> &requestRawMsg);

    // Inject companion request + capture + decode reply. For companion-side tests.
    std::optional<RawMsgInfo> InjectRequestAndCaptureReply(const std::string &connName,
        const std::vector<uint8_t> &requestRawMsg, MessageType expectedType);

    // Host-side: SetSubscribeMode + SimulateDeviceOnline + build sync reply + inject + drain.
    void SetupHostSideSync(const std::string &companionDeviceId, UserId hostUserId);

    // Real Executor access - call this for E2E tests instead of direct singleton access
    std::shared_ptr<FwkIAuthExecutorHdi> GetExecutor();

private:
    bool RegisterDeviceSelectCallback(uint32_t tokenId);
    bool UnregisterDeviceSelectCallback(uint32_t tokenId);
    void SetupDefaultValues();

    // Sub-operations for RegisterCompanionViaMessageFlow
    void SetupEnrollSecurityAgentMocks(TemplateId templateId);
    bool PerformRegistrationHandshake(const std::string &connName);
    bool VerifyCompanionPersisted(UserId hostUserId, const DeviceKey &companionDeviceKey, TemplateId templateId);

    // Sub-operations for RegisterCompanionDirect
    void SetupEndAddCompanionMock(TemplateId templateId);
    void InjectDefaultSyncReply(const DeviceKey &companionDeviceKey, UserId hostUserId);

    std::shared_ptr<TestServiceInitializer> initializer_;
    std::shared_ptr<BaseServiceCore> core_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_MODULETEST_SERVICES_MODULE_TEST_GUARD_H
