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

#include "module_test_guard.h"
#include "module_test_helpers.h"

#include <gmock/gmock.h>

#include "iam_logger.h"
#include "relative_timer.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "attributes.h"
#include "base_service_core.h"
#include "companion_manager.h"
#include "host_binding_manager.h"
#include "request_factory.h"
#include "request_manager.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "subscription_manager.h"
#include "system_param_manager.h"

// For RegisterCompanionViaMessageFlow E2E message flow
#include "add_companion_message.h"
#include "common_message.h"
#include "cross_device_comm_manager.h"
#include "sync_device_status_message.h"

#define LOG_TAG "CDA_SA_MODULE_TEST"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using namespace testing;

// ============================================================================
// TestServiceInitializer
// ============================================================================

TestServiceInitializer::TestServiceInitializer(std::shared_ptr<SubscriptionManager> subscriptionManager)
    : BaseServiceInitializer(subscriptionManager,
          DeviceCapabilityInfo { { BusinessId::DEFAULT },
              { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN }, { BusinessId::DEFAULT },
              { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } },
          true) // hostBindingRevokeTokenOnInactive
{
}

std::shared_ptr<TestServiceInitializer> TestServiceInitializer::Create()
{
    auto subscriptionManager = std::make_shared<SubscriptionManager>();
    auto initializer = std::make_shared<TestServiceInitializer>(subscriptionManager);
    if (!initializer || !initializer->Initialize()) {
        IAM_LOGE("TestServiceInitializer::Create failed");
        return nullptr;
    }
    return initializer;
}

// ============================================================================
// AdapterManager injections — override base to inject test doubles
// ============================================================================

bool TestServiceInitializer::InitializeTimeKeeper()
{
    timeKeeper_ = std::make_shared<MockTimeKeeper>();
    AdapterManager::GetInstance().SetTimeKeeper(timeKeeper_);
    return true;
}

bool TestServiceInitializer::InitializeEventManagerAdapter()
{
    eventManagerAdapter_ = std::make_shared<MockEventManagerAdapter>();
    AdapterManager::GetInstance().SetEventManagerAdapter(eventManagerAdapter_);
    return true;
}

bool TestServiceInitializer::InitializeSaManagerAdapter()
{
    saManagerAdapter_ = std::make_shared<FakeSaManagerAdapter>();
    AdapterManager::GetInstance().SetSaManagerAdapter(saManagerAdapter_);
    return true;
}

bool TestServiceInitializer::InitializeSecurityCommandAdapter()
{
    // STATIC_LIBRARY build — production SecurityCommandAdapterImpl not available.
    // Inject nothing; SecurityCommandAdapter is not needed for module tests.
    return true;
}

bool TestServiceInitializer::InitializeSystemParamManager()
{
    systemParamManager_ = std::make_shared<FakeSystemParamManager>();
    AdapterManager::GetInstance().SetSystemParamManager(systemParamManager_);
    return true;
}

bool TestServiceInitializer::InitializeUserIdManager()
{
    userIdManager_ = std::make_shared<FakeUserIdManager>();
    AdapterManager::GetInstance().SetUserIdManager(userIdManager_);
    return true;
}

bool TestServiceInitializer::InitializeUserAuthFramework()
{
    userAuthAdapter_ = std::make_shared<MockUserAuthAdapter>();
    AdapterManager::GetInstance().SetUserAuthAdapter(userAuthAdapter_);

    driverManagerAdapter_ = std::make_shared<FakeDriverManagerAdapter>();
    AdapterManager::GetInstance().SetDriverManagerAdapter(driverManagerAdapter_);

    idmAdapter_ = std::make_shared<FakeIdmAdapter>();
    AdapterManager::GetInstance().SetIdmAdapter(idmAdapter_);
    return true;
}

// ============================================================================
// SingletonManager injections
// ============================================================================

bool TestServiceInitializer::InitializeMiscManager()
{
    miscManager_ = std::make_shared<FakeMiscManager>();
    SingletonManager::GetInstance().SetMiscManager(miscManager_);
    return true;
}

bool TestServiceInitializer::InitializeSecurityAgent()
{
    securityAgent_ = std::make_shared<MockSecurityAgent>();
    SingletonManager::GetInstance().SetSecurityAgent(securityAgent_);
    SetupSecurityAgentDefaults();
    return true;
}

void TestServiceInitializer::SetupSecurityAgentDefaults()
{
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
    ON_CALL(*securityAgent_, HostEndAddCompanion(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostRemoveCompanion(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostUpdateCompanionStatus(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostUpdateCompanionEnabledBusinessIds(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(*securityAgent_, HostRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
}

// ============================================================================
// Channel injection — FakeChannel instead of SoftBus
// ============================================================================

bool TestServiceInitializer::InitializeChannels()
{
    channel_ = std::make_shared<FakeChannel>();
    channelsHolder_.push_back(channel_);
    return true;
}

// ============================================================================
// Accessors
// ============================================================================

FakeChannel &TestServiceInitializer::GetChannel()
{
    return *channel_;
}
MockTimeKeeper &TestServiceInitializer::GetTimeKeeper()
{
    return *timeKeeper_;
}
FakeUserIdManager &TestServiceInitializer::GetUserIdManager()
{
    return *userIdManager_;
}
FakeSystemParamManager &TestServiceInitializer::GetSystemParamManager()
{
    return *systemParamManager_;
}
FakeMiscManager &TestServiceInitializer::GetMiscManager()
{
    return *miscManager_;
}
FakeIdmAdapter &TestServiceInitializer::GetIdmAdapter()
{
    return *idmAdapter_;
}
FakeSaManagerAdapter &TestServiceInitializer::GetSaManagerAdapter()
{
    return *saManagerAdapter_;
}
FakeDriverManagerAdapter &TestServiceInitializer::GetDriverManagerAdapter()
{
    return *driverManagerAdapter_;
}
MockUserAuthAdapter &TestServiceInitializer::GetUserAuthAdapter()
{
    return *userAuthAdapter_;
}
MockEventManagerAdapter &TestServiceInitializer::GetEventManagerAdapter()
{
    return *eventManagerAdapter_;
}
MockSecurityAgent &TestServiceInitializer::GetSecurityAgent()
{
    return *securityAgent_;
}

std::shared_ptr<MockSecurityAgent> TestServiceInitializer::GetSecurityAgentPtr() const
{
    return securityAgent_;
}
std::shared_ptr<MockUserAuthAdapter> TestServiceInitializer::GetUserAuthAdapterPtr() const
{
    return userAuthAdapter_;
}
std::shared_ptr<MockEventManagerAdapter> TestServiceInitializer::GetEventManagerAdapterPtr() const
{
    return eventManagerAdapter_;
}

// ============================================================================
// ModuleTestGuard — composition wrapper
// ============================================================================

ModuleTestGuard::ModuleTestGuard()
{
    SingletonManager::GetInstance().Reset();
    AdapterManager::GetInstance().Reset();

    // 1. Run 12-step init pipeline with Fake/Mock injection
    initializer_ = TestServiceInitializer::Create();

    // 1b. Link RelativeTimer's time source to MockTimeKeeper's steady time.
    // This ensures RelativeTimer respects time advancements for timeout testing.
    RelativeTimer::GetInstance().SetTimeProvider([&timeKeeper = initializer_->GetTimeKeeper()]() -> uint64_t {
        auto steady = timeKeeper.GetSteadyTimeMs();
        return steady.has_value() ? static_cast<uint64_t>(*steady) : 0ULL;
    });

    // 2. Create BaseServiceCore directly (mimics OnStart without CompanionDeviceAuthService).
    // The OH GN build links against real libutils.z.so whose RefBase/sptr/wptr implementation
    // is incompatible with test-constructed CompanionDeviceAuthService (multiple inheritance
    // with SystemAbility + CompanionDeviceAuthStub). Module tests don't use any service IPC
    // APIs, so we skip the full service creation and only create the core.
    core_ = BaseServiceCore::Create(initializer_->GetSubscriptionManager(), initializer_->GetHostSupportedBusinessIds(),
        initializer_->GetCompanionSupportedBusinessIds());

    // 3. Set function-ready param (mimics OnStart's delayed PostTask)
    RelativeTimer::GetInstance().PostTask(
        []() {
            OHOS::UserIam::CompanionDeviceAuth::GetSystemParamManager().SetParam(CDA_IS_FUNCTION_READY_KEY, TRUE_STR);
        },
        0);

    // 4. Drain pending tasks until quiescent
    static constexpr int32_t DEFAULT_DRAIN_ITERATIONS = 10;
    for (int i = 0; i < DEFAULT_DRAIN_ITERATIONS; ++i) {
        TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
        RelativeTimer::GetInstance().DrainExpiredTasks();
    }

    // 5. Set proper default values on all Fakes/Mocks
    SetupDefaultValues();
}

ModuleTestGuard::~ModuleTestGuard()
{
    // Drain all pending work before teardown
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    RelativeTimer::GetInstance().DrainExpiredTasks();

    // Clear gmock expectations for all Mocks
    if (initializer_) {
        Mock::VerifyAndClearExpectations(initializer_->GetSecurityAgentPtr().get());
        Mock::VerifyAndClearExpectations(initializer_->GetUserAuthAdapterPtr().get());
        Mock::VerifyAndClearExpectations(initializer_->GetEventManagerAdapterPtr().get());
    }

    // Clear core before resetting singletons
    core_ = nullptr;

    SingletonManager::GetInstance().Reset();
    AdapterManager::GetInstance().Reset();
}

void ModuleTestGuard::SetupDefaultValues()
{
    // FakeUserIdManager: set default active user
    // Production: UserIdManager subscribes to active user changes via SA framework
    static constexpr UserId DEFAULT_ACTIVE_USER_ID = 100;
    static constexpr int64_t DEFAULT_TIME_ADVANCE_MS = 5000;
    initializer_->GetUserIdManager().TestSetActiveUser(DEFAULT_ACTIVE_USER_ID, "TestUser");

    // MockTimeKeeper: advance to a reasonable time
    initializer_->GetTimeKeeper().AdvanceSystemTime(DEFAULT_TIME_ADVANCE_MS);
    initializer_->GetTimeKeeper().AdvanceSteadyTime(DEFAULT_TIME_ADVANCE_MS);

    // MockUserAuthAdapter: reasonable ON_CALL defaults
    ON_CALL(initializer_->GetUserAuthAdapter(), BeginDelegateAuth(_))
        .WillByDefault(Return(1)); // non-zero contextId = success
    ON_CALL(initializer_->GetUserAuthAdapter(), CancelAuthentication(_)).WillByDefault(Return(0)); // SUCCESS
}

void ModuleTestGuard::SimulateDeviceOnline(const std::string &deviceId)
{
    GetChannel().TestSimulateDeviceOnline(MakePhysKey(deviceId));
    DrainPendingTasks();
}

bool ModuleTestGuard::RegisterCompanion(UserId hostUser, const std::string &deviceId, TemplateId templateId)
{
    return RegisterCompanionDirect(hostUser, MakeDeviceKey(deviceId, hostUser), templateId);
}

bool ModuleTestGuard::SetupCompanionDevice(UserId hostUser, const std::string &deviceId, TemplateId templateId)
{
    SimulateDeviceOnline(deviceId);
    return RegisterCompanion(hostUser, deviceId, templateId);
}

bool ModuleTestGuard::SetupHostBinding(UserId companionUserId, const std::string &hostDeviceId, BindingId bindingId)
{
    return RegisterHostBindingDirect(companionUserId, MakeDeviceKey(hostDeviceId, companionUserId), bindingId);
}

// Delegate all accessors to the held TestServiceInitializer

FakeChannel &ModuleTestGuard::GetChannel()
{
    return initializer_->GetChannel();
}
MockTimeKeeper &ModuleTestGuard::GetTimeKeeper()
{
    return initializer_->GetTimeKeeper();
}
FakeUserIdManager &ModuleTestGuard::GetUserIdManager()
{
    return initializer_->GetUserIdManager();
}
FakeSystemParamManager &ModuleTestGuard::GetSystemParamManager()
{
    return initializer_->GetSystemParamManager();
}
FakeMiscManager &ModuleTestGuard::GetMiscManager()
{
    return initializer_->GetMiscManager();
}
FakeIdmAdapter &ModuleTestGuard::GetIdmAdapter()
{
    return initializer_->GetIdmAdapter();
}
FakeSaManagerAdapter &ModuleTestGuard::GetSaManagerAdapter()
{
    return initializer_->GetSaManagerAdapter();
}
FakeDriverManagerAdapter &ModuleTestGuard::GetDriverManagerAdapter()
{
    return initializer_->GetDriverManagerAdapter();
}
MockUserAuthAdapter &ModuleTestGuard::GetUserAuthAdapter()
{
    return initializer_->GetUserAuthAdapter();
}
MockEventManagerAdapter &ModuleTestGuard::GetEventManagerAdapter()
{
    return initializer_->GetEventManagerAdapter();
}
MockSecurityAgent &ModuleTestGuard::GetSecurityAgent()
{
    return initializer_->GetSecurityAgent();
}

std::shared_ptr<FwkIAuthExecutorHdi> ModuleTestGuard::GetExecutor()
{
    return initializer_->GetDriverManagerAdapter().TestGetRegisteredExecutor();
}

// ============================================================================
// Executor-like helper implementations
// ============================================================================

bool ModuleTestGuard::Enroll(ScheduleId scheduleId, const std::vector<uint8_t> &extraInfo, TemplateId tokenId,
    const std::string &additionalInfo, FwkResultCallback &&callback)
{
    // Register device selection callback before starting the request
    // This is required by HostAddCompanionRequest::OnStart which calls GetDeviceDeviceSelectResult
    if (!RegisterDeviceSelectCallback(tokenId)) {
        IAM_LOGE("RegisterDeviceSelectCallback failed for tokenId %{public}llu",
            static_cast<unsigned long long>(tokenId));
        return false;
    }

    // Build fwkMsg with additionalInfo as attribute (mimics Executor.Enroll() lines 159-165)
    std::vector<uint8_t> fwkMsg = extraInfo;
    if (!additionalInfo.empty()) {
        Attributes fwkAttributes;
        fwkAttributes.SetUint8ArrayValue(Attributes::AttributeKey::ATTR_CDA_SA_EXTRA_INFO,
            std::vector<uint8_t>(additionalInfo.begin(), additionalInfo.end()));
        fwkMsg = fwkAttributes.Serialize();
    }

    // Create HostAddCompanionRequest (mimics Executor.Enroll() lines 167-168)
    auto request = GetRequestFactory().CreateHostAddCompanionRequest(scheduleId, fwkMsg, tokenId, additionalInfo,
        std::move(callback));
    if (request == nullptr) {
        IAM_LOGE("CreateHostAddCompanionRequest failed");
        UnregisterDeviceSelectCallback(tokenId);
        return false;
    }

    // Start the request (mimics Executor.Enroll() line 175)
    return GetRequestManager().Start(request);
}

bool ModuleTestGuard::AuthenticateTokenAuth(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg, UserId userId,
    TemplateId templateId, uint32_t lockStateAuthType, FwkResultCallback &&callback)
{
    // Create HostTokenAuthRequest (mimics Executor.Authenticate() for TokenAuth)
    AuthRequestParams params = { scheduleId, fwkMsg, userId, templateId, static_cast<int32_t>(lockStateAuthType),
        UserAuth::AUTH_SCENE_DEFAULT };
    auto request = GetRequestFactory().CreateHostTokenAuthRequest(params, std::move(callback));
    if (request == nullptr) {
        IAM_LOGE("CreateHostTokenAuthRequest failed");
        return false;
    }

    return GetRequestManager().Start(request);
}

bool ModuleTestGuard::AuthenticateDelegateAuth(ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg, UserId userId,
    TemplateId templateId, uint32_t authIntent, FwkResultCallback &&callback)
{
    // Create HostDelegateAuthRequest (mimics Executor.Authenticate() for DelegateAuth)
    AuthRequestParams params = { scheduleId, fwkMsg, userId, templateId, static_cast<int32_t>(authIntent),
        UserAuth::AUTH_SCENE_DEFAULT };
    auto request = GetRequestFactory().CreateHostDelegateAuthRequest(params, std::move(callback));
    if (request == nullptr) {
        IAM_LOGE("CreateHostDelegateAuthRequest failed");
        return false;
    }

    return GetRequestManager().Start(request);
}

void ModuleTestGuard::StartIssueTokenRequests(const std::vector<TemplateId> &templateIds, uint32_t lockStateAuthType,
    const std::vector<uint8_t> &fwkUnlockMsg, FwkResultCallback &&callback)
{
    // Use CompanionManager.StartIssueTokenRequests() (production path)
    // Note: This starts async requests; callback will be invoked when complete
    GetCompanionManager().StartIssueTokenRequests(templateIds, lockStateAuthType, fwkUnlockMsg);
    // The callback is handled internally by the manager; tests should verify via other means
    (void)callback; // Callback not directly supported by manager API - tests verify via side effects
}

ResultCode ModuleTestGuard::RemoveCompanion(TemplateId templateId, FwkResultCallback &&callback)
{
    // Use CompanionManager.RemoveCompanion() (production path)
    // Note: This is a synchronous operation; callback is provided for test convenience
    ResultCode ret = GetCompanionManager().RemoveCompanion(templateId, true);
    if (callback) {
        callback(ret, {});
    }
    return ret;
}

void ModuleTestGuard::SetupEnrollSecurityAgentMocks(TemplateId templateId)
{
    static constexpr Atl FLOW_ATL = 2;
    static constexpr int32_t FLOW_ESL = 1;
    static constexpr int64_t FLOW_ADDED_TIME = 1000;
    static const std::vector<uint8_t> MOCK_FWK_MSG = { 0x07, 0x08 };
    static const std::vector<uint8_t> MOCK_TOKEN_DATA = { 0x09, 0x0A };

    HostGetInitKeyNegotiationRequestOutput initReqOutput;
    initReqOutput.initKeyNegotiationRequest = { 0x01, 0x02, 0x03 };
    initReqOutput.algorithmList = { 1, 2 };
    EXPECT_CALL(GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(initReqOutput), Return(ResultCode::SUCCESS)));

    HostBeginAddCompanionOutput beginCompOutput;
    beginCompOutput.addHostBindingRequest = { 0x04, 0x05, 0x06 };
    beginCompOutput.selectedAlgorithm = 1;
    EXPECT_CALL(GetSecurityAgent(), HostBeginAddCompanion(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(beginCompOutput), Return(ResultCode::SUCCESS)));

    HostEndAddCompanionOutput endCompOutput;
    endCompOutput.fwkMsg = MOCK_FWK_MSG;
    endCompOutput.templateId = templateId;
    endCompOutput.tokenData = MOCK_TOKEN_DATA;
    endCompOutput.atl = FLOW_ATL;
    endCompOutput.esl = FLOW_ESL;
    endCompOutput.addedTime = FLOW_ADDED_TIME;
    EXPECT_CALL(GetSecurityAgent(), HostEndAddCompanion(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(endCompOutput), Return(ResultCode::SUCCESS)));
}

bool ModuleTestGuard::PerformRegistrationHandshake(const std::string &connName)
{
    InitKeyNegotiationReply initReply;
    initReply.result = ResultCode::SUCCESS;
    initReply.extraInfo = { 0xCC, 0xDD };
    Attributes initReplyPayload;
    EncodeInitKeyNegotiationReply(initReply, initReplyPayload);
    if (!CaptureAndReply(GetChannel(), connName, MessageType::INIT_KEY_NEGOTIATION, initReplyPayload)) {
        IAM_LOGE("Round 1: INIT_KEY_NEGOTIATION capture/reply failed");
        return false;
    }

    BeginAddHostBindingReply beginReply;
    beginReply.result = ResultCode::SUCCESS;
    beginReply.extraInfo = { 0xEE, 0xFF };
    Attributes beginReplyPayload;
    EncodeBeginAddHostBindingReply(beginReply, beginReplyPayload);
    if (!CaptureAndReply(GetChannel(), connName, MessageType::BEGIN_ADD_HOST_BINDING, beginReplyPayload)) {
        IAM_LOGE("Round 2: BEGIN_ADD_HOST_BINDING capture/reply failed");
        return false;
    }

    EndAddHostBindingReply endReply;
    endReply.result = ResultCode::SUCCESS;
    Attributes endReplyPayload;
    EncodeEndAddHostBindingReply(endReply, endReplyPayload);
    if (!CaptureAndReply(GetChannel(), connName, MessageType::END_ADD_HOST_BINDING, endReplyPayload)) {
        IAM_LOGE("Round 3: END_ADD_HOST_BINDING capture/reply failed");
        return false;
    }
    return true;
}

bool ModuleTestGuard::RegisterCompanionViaMessageFlow(UserId hostUserId, const DeviceKey &companionDeviceKey,
    TemplateId templateId, UserId companionUserId)
{
    constexpr ScheduleId TEST_SCHEDULE_ID = 10001;
    constexpr uint32_t TEST_TOKEN_ID = 9999;
    const std::string TEST_ADDITIONAL_INFO = R"({"enabled_business_ids":[1,2]})";

    PhysicalDeviceKey companionPhysKey;
    companionPhysKey.idType = companionDeviceKey.idType;
    companionPhysKey.deviceId = companionDeviceKey.deviceId;
    GetChannel().TestSimulateDeviceOnline(companionPhysKey);
    DrainPendingTasks();

    SetupEnrollSecurityAgentMocks(templateId);

    bool callbackInvoked = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    auto fwkCallback = [&](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackInvoked = true;
        callbackResult = result;
        (void)extraInfo;
    };

    bool enrollRet =
        Enroll(TEST_SCHEDULE_ID, { 0xAA, 0xBB }, TEST_TOKEN_ID, TEST_ADDITIONAL_INFO, std::move(fwkCallback));
    if (!enrollRet) {
        IAM_LOGE("Enroll failed");
        return false;
    }
    DrainPendingTasks();

    DeviceKey selectedDevice;
    selectedDevice.idType = companionDeviceKey.idType;
    selectedDevice.deviceId = companionDeviceKey.deviceId;
    selectedDevice.deviceUserId = hostUserId;
    GetMiscManager().TestSimulateDeviceSelectResult(TEST_TOKEN_ID, { selectedDevice });
    DrainPendingTasks();

    auto allConnNames = GetChannel().GetAllConnectionNames();
    if (allConnNames.empty()) {
        IAM_LOGE("No connection established");
        return false;
    }
    const auto &connName = allConnNames[0];

    if (!PerformRegistrationHandshake(connName)) {
        return false;
    }

    if (!callbackInvoked || callbackResult != ResultCode::SUCCESS) {
        IAM_LOGE("Callback not invoked or failed: invoked=%{public}d, result=%{public}d", callbackInvoked,
            static_cast<int>(callbackResult));
        return false;
    }
    return VerifyCompanionPersisted(hostUserId, companionDeviceKey, templateId);
}

bool ModuleTestGuard::VerifyCompanionPersisted(UserId hostUserId, const DeviceKey &companionDeviceKey,
    TemplateId templateId)
{
    DeviceKey queryKey;
    queryKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    queryKey.deviceId = companionDeviceKey.deviceId;
    queryKey.deviceUserId = hostUserId;
    auto companionStatus = GetCompanionManager().GetCompanionStatus(hostUserId, queryKey);
    if (!companionStatus.has_value()) {
        IAM_LOGE("Companion status not persisted");
        return false;
    }
    if (companionStatus->templateId != templateId) {
        IAM_LOGE("Template ID mismatch: expected=%u, actual=%u", static_cast<uint32_t>(templateId),
            static_cast<uint32_t>(companionStatus->templateId));
        return false;
    }
    return true;
}

bool ModuleTestGuard::RegisterDeviceSelectCallback(uint32_t tokenId)
{
    // Register directly via FakeMiscManager (bypasses IPC stub creation).
    // FakeMiscManager stores the callback pointer but only uses it for
    // GetDeviceDeviceSelectResult → TestSimulateDeviceSelectResult flow.
    // Passing nullptr is fine because FakeMiscManager's GetDeviceDeviceSelectResult
    // doesn't invoke the IIpcDeviceSelectCallback; it only stores a DeviceSelectResultHandler.
    return GetMiscManager().SetDeviceSelectCallback(tokenId, nullptr);
}

bool ModuleTestGuard::UnregisterDeviceSelectCallback(uint32_t tokenId)
{
    if (core_ == nullptr) {
        IAM_LOGE("Core is null");
        return false;
    }

    ResultCode ret = core_->UnregisterDeviceSelectCallback(tokenId);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("UnregisterDeviceSelectCallback failed: %d", static_cast<int>(ret));
        return false;
    }

    return true;
}

void ModuleTestGuard::SetupEndAddCompanionMock(TemplateId templateId)
{
    static constexpr Atl DEFAULT_ATL = 2;
    static constexpr int32_t DEFAULT_ESL = 1;
    static constexpr int64_t DEFAULT_ADDED_TIME = 1000;
    static const std::vector<uint8_t> MOCK_FWK_MSG = { 0xAA, 0xBB };
    static const std::vector<uint8_t> MOCK_TOKEN_DATA = { 0x01, 0x02 };

    HostEndAddCompanionOutput secOutput;
    secOutput.fwkMsg = MOCK_FWK_MSG;
    secOutput.templateId = templateId;
    secOutput.tokenData = MOCK_TOKEN_DATA;
    secOutput.atl = DEFAULT_ATL;
    secOutput.esl = DEFAULT_ESL;
    secOutput.addedTime = DEFAULT_ADDED_TIME;
    EXPECT_CALL(GetSecurityAgent(), HostEndAddCompanion(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(secOutput), Return(ResultCode::SUCCESS)));
}

void ModuleTestGuard::InjectDefaultSyncReply(const DeviceKey &companionDeviceKey, UserId hostUserId)
{
    SyncDeviceStatusReply syncReply;
    syncReply.result = ResultCode::SUCCESS;
    syncReply.protocolIdList = { ProtocolId::VERSION_1 };
    syncReply.capabilityList = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN };
    syncReply.secureProtocolId = SecureProtocolId::DEFAULT;
    syncReply.companionDeviceKey = companionDeviceKey;
    syncReply.companionDeviceKey.deviceUserId = hostUserId;
    syncReply.deviceUserName = "test-user";
    InjectSyncDeviceStatusReply(GetChannel(), syncReply, companionDeviceKey);
    DrainPendingTasks();
}

bool ModuleTestGuard::RegisterCompanionDirect(UserId hostUserId, const DeviceKey &companionDeviceKey,
    TemplateId templateId, const std::vector<BusinessId> &enabledBusinessIds)
{
    PersistedCompanionStatus companionStatus;
    companionStatus.templateId = templateId;
    companionStatus.hostUserId = hostUserId;
    companionStatus.companionDeviceKey = companionDeviceKey;
    companionStatus.deviceUserName = "test-device";
    companionStatus.deviceModelInfo = "test-model";
    companionStatus.deviceName = "test-name";
    companionStatus.addedTime = 0;
    companionStatus.isValid = true;
    companionStatus.enabledBusinessIds = enabledBusinessIds;
    companionStatus.deviceType = DeviceType::UNKNOWN;

    SetupEndAddCompanionMock(templateId);

    EndAddCompanionInput endInput;
    endInput.requestId = 0;
    endInput.companionStatus = companionStatus;
    endInput.secureProtocolId = SecureProtocolId::DEFAULT;
    endInput.protocolVersionList = { 1 };
    endInput.capabilityList = { static_cast<uint16_t>(Capability::DELEGATE_AUTH),
        static_cast<uint16_t>(Capability::TOKEN_AUTH) };
    endInput.addHostBindingReply = {};

    EndAddCompanionOutput endOutput;
    ResultCode ret = GetCompanionManager().EndAddCompanion(endInput, endOutput);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("EndAddCompanion failed: %d", static_cast<int>(ret));
        return false;
    }

    GetIdmAdapter().TestAddTemplate(hostUserId, templateId);
    GetIdmAdapter().TestSimulateTemplateChange(hostUserId, { templateId });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    GetCompanionManager().SetCompanionTokenAuthAtl(templateId, 1);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    auto statusCheck = GetCompanionManager().GetCompanionStatus(templateId);
    if (!statusCheck.has_value()) {
        IAM_LOGE("RegisterCompanionDirect: GetCompanionStatus still returns nullopt after setup");
        return false;
    }

    InjectDefaultSyncReply(companionDeviceKey, hostUserId);

    IAM_LOGI("RegisterCompanionDirect: templateId=%{public}s, hostUserId=%{public}d",
        GET_TRUNCATED_STRING(templateId).c_str(), hostUserId);
    return true;
}

bool ModuleTestGuard::RegisterHostBindingDirect(UserId companionUserId, const DeviceKey &hostDeviceKey,
    BindingId bindingId)
{
    // Build a PersistedHostBindingStatus for the host binding
    PersistedHostBindingStatus persistedStatus;
    persistedStatus.bindingId = bindingId;
    persistedStatus.companionUserId = companionUserId;
    persistedStatus.hostDeviceKey = hostDeviceKey;
    persistedStatus.isTokenValid = false;

    // Setup mock: CompanionBeginAddHostBinding returns our persistedStatus
    CompanionBeginAddHostBindingOutput secOutput;
    secOutput.addHostBindingReply = { 0x01, 0x02, 0x03 };
    secOutput.hostBindingStatus = persistedStatus;
    EXPECT_CALL(GetSecurityAgent(), CompanionBeginAddHostBinding(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(secOutput), Return(ResultCode::SUCCESS)));

    // Call BeginAddHostBinding through the manager
    BeginAddHostBindingInput input;
    input.requestId = 0;
    input.companionUserId = companionUserId;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.addHostBindingRequest = { 0xAA, 0xBB };

    BeginAddHostBindingOutput output;
    ResultCode ret = GetHostBindingManager().BeginAddHostBinding(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("RegisterHostBindingDirect: BeginAddHostBinding failed: %d", static_cast<int>(ret));
        return false;
    }

    // Verify binding is queryable
    auto status = GetHostBindingManager().GetHostBindingStatus(companionUserId, hostDeviceKey);
    if (!status.has_value()) {
        IAM_LOGE("RegisterHostBindingDirect: GetHostBindingStatus returns nullopt");
        return false;
    }

    IAM_LOGI("RegisterHostBindingDirect: bindingId=%u, companionUserId=%u", static_cast<uint32_t>(bindingId),
        companionUserId);
    return true;
}

// ============================================================================
// Message flow helpers
// ============================================================================

std::string ModuleTestGuard::GetAnyConnectionName()
{
    auto names = GetChannel().GetAllConnectionNames();
    return names.empty() ? std::string() : names.back();
}

std::optional<RawMsgInfo> ModuleTestGuard::CaptureOutboundMessage(const std::string &connName, MessageType expectedType)
{
    auto sentMsgs = GetChannel().GetSentMessages(connName);
    if (sentMsgs.empty()) {
        return std::nullopt;
    }
    auto msgInfo = DecodeRawMsg(sentMsgs[0]);
    if (!msgInfo.has_value() || msgInfo->msgType != expectedType) {
        return std::nullopt;
    }
    return msgInfo;
}

void ModuleTestGuard::InjectTypedReply(const std::string &connName, uint32_t seq, MessageType msgType,
    const Attributes &replyPayload)
{
    auto replyRawMsg = BuildReplyRawMsg(connName, seq, msgType, replyPayload);
    GetChannel().ClearSentMessages();
    GetChannel().TestSimulateIncomingMessage(connName, replyRawMsg);
    DrainPendingTasks();
}

std::optional<RawMsgInfo> ModuleTestGuard::CaptureVerifyAndReply(const std::string &connName, MessageType expectedType,
    const Attributes &replyPayload)
{
    auto msgInfo = CaptureOutboundMessage(connName, expectedType);
    if (!msgInfo.has_value()) {
        return std::nullopt;
    }
    InjectTypedReply(connName, msgInfo->seq, expectedType, replyPayload);
    return msgInfo;
}

void ModuleTestGuard::InjectCompanionRequest(const std::string &connName, const std::vector<uint8_t> &requestRawMsg)
{
    GetChannel().ClearSentMessages();
    GetChannel().TestSimulateIncomingMessage(connName, requestRawMsg);
    DrainPendingTasks();
}

std::optional<RawMsgInfo> ModuleTestGuard::InjectRequestAndCaptureReply(const std::string &connName,
    const std::vector<uint8_t> &requestRawMsg, MessageType expectedType)
{
    InjectCompanionRequest(connName, requestRawMsg);
    auto sentMsgs = GetChannel().GetSentMessages(connName);
    if (sentMsgs.empty()) {
        return std::nullopt;
    }
    auto replyInfo = DecodeRawMsg(sentMsgs[0]);
    if (!replyInfo.has_value() || !replyInfo->isReply || replyInfo->msgType != expectedType) {
        return std::nullopt;
    }
    return replyInfo;
}

void ModuleTestGuard::SetupHostSideSync(const std::string &companionDeviceId, UserId hostUserId)
{
    GetCrossDeviceCommManager().SetSubscribeMode(SUBSCRIBE_MODE_MANAGE);
    SimulateDeviceOnline(companionDeviceId);
    SyncDeviceStatusReply syncReply;
    syncReply.result = ResultCode::SUCCESS;
    syncReply.protocolIdList = { ProtocolId::VERSION_1 };
    syncReply.capabilityList = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH };
    syncReply.secureProtocolId = SecureProtocolId::DEFAULT;
    syncReply.companionDeviceKey = MakeDeviceKey(companionDeviceId, hostUserId);
    syncReply.deviceUserName = "TestCompanion";
    InjectSyncDeviceStatusReply(GetChannel(), syncReply, MakeDeviceKey(companionDeviceId, hostUserId));
    DrainPendingTasks();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
