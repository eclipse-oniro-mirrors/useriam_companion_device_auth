/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_event_manager_adapter.h"
#include "mock_misc_manager.h"
#include "mock_request.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_time_keeper.h"
#include "mock_user_key_manager.h"

#include "adapter_manager.h"
#include "host_sync_device_status_request.h"
#include "relative_timer.h"
#include "service_converter.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t HOST_USER_ID = 100;
// Value reserved for a future VERSION_2 that ProtocolId does not define yet.
constexpr ProtocolId PROTOCOL_VERSION_2 = static_cast<ProtocolId>(2);
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };
const DeviceKey HOST_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "host_device_id",
    .deviceUserId = 100 };
constexpr ConnectionMode CONNECTION_MODE = ConnectionMode::BACKGROUND;
const LocalDeviceProfile PROFILE = { .protocols = { ProtocolId::VERSION_1 },
    .hostCapabilities = { Capability::TOKEN_AUTH },
    .companionCapabilities = { Capability::TOKEN_AUTH } };

SyncDeviceStatusReply MakeDefaultSyncDeviceStatusReply()
{
    return {
        .result = ResultCode::SUCCESS,
        .companionProtocolIdList = { ProtocolId::VERSION_1 },
        .companionCapabilityList = { Capability::TOKEN_AUTH },
        .businessIdList = { BusinessId::DEFAULT },
        .secureProtocolId = SecureProtocolId::DEFAULT,
        .companionDeviceKey = COMPANION_DEVICE_KEY,
        .deviceUserName = "test_user_name",
        .companionCheckResponse = { 1, 2, 3 },
    };
}

CompanionStatus MakeBoundCompanionStatus()
{
    CompanionStatus bound;
    bound.templateId = HOST_USER_ID;
    bound.isValid = true;
    bound.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    bound.enrolledProtocolId = ProtocolId::VERSION_1;
    return bound;
}

class HostSyncDeviceStatusRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto userKeyMgr = std::shared_ptr<IUserKeyManager>(&mockUserKeyManager_, [](IUserKeyManager *) {});
        AdapterManager::GetInstance().SetUserKeyManager(userKeyMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        auto eventManagerAdapter =
            std::shared_ptr<IEventManagerAdapter>(&mockEventManagerAdapter_, [](IEventManagerAdapter *) {});
        AdapterManager::GetInstance().SetEventManagerAdapter(eventManagerAdapter);

        ON_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(HOST_DEVICE_KEY)));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(PROFILE));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
        ON_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).WillByDefault(Return());
        ON_CALL(mockEventManagerAdapter_, ReportInteractionEvent(_)).WillByDefault(Return());
        ON_CALL(mockUserKeyManager_, GetForegroundSubProfileId(_)).WillByDefault(Return(INVALID_SUB_PROFILE_ID));
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserKeyManager> mockUserKeyManager_;
    NiceMock<MockEventManagerAdapter> mockEventManagerAdapter_;
};

HWTEST_F(HostSyncDeviceStatusRequestTest, OnConnected_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(PROFILE));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    ASSERT_NO_THROW(request->OnConnected());
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_001, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::FAIL) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::FAIL));

    request->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_002, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_003, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, SendSyncDeviceStatusRequest_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(PROFILE));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    std::vector<uint8_t> salt;
    uint64_t challenge = 0;
    bool result = request->SendSyncDeviceStatusRequest(salt, challenge);

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_001, TestSize.Level0)
{
    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    Attributes reply;
    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply.companionDeviceKey.deviceId);

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request->hostProtocolIdList_ = PROFILE.protocols;
    request->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_002, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    Attributes reply;
    request->hostProtocolIdList_ = PROFILE.protocols;
    request->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_003, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    // Generic peer failures collapse into PEER_SYNC_FAILED; terminal errors
    // (PROTOCOL_NEGOTIATION_FAILED, SECURE_PROTOCOL_NOT_SUPPORTED, NOT_ENROLLED) pass through
    // verbatim so the caller aborts the retry.
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::PEER_SYNC_FAILED) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    Attributes reply;
    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    syncDeviceStatusReply.result = ResultCode::GENERAL_ERROR;
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply.companionDeviceKey.deviceId);

    request->hostProtocolIdList_ = PROFILE.protocols;
    request->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_004, TestSize.Level0)
{
    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    Attributes reply;
    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply.companionDeviceKey.deviceId);

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request->cancelCompanionCheckGuard_ = nullptr;
    request->hostProtocolIdList_ = PROFILE.protocols;
    request->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::GENERAL_ERROR,
        .businessIdList = { BusinessId::DEFAULT } };
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply, request->QueryCompanionStatus(syncDeviceStatusReply),
        authenticatedCapabilities);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_002, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .businessIdList = { BusinessId::DEFAULT } };
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply, request->QueryCompanionStatus(syncDeviceStatusReply),
        authenticatedCapabilities);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_003, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .businessIdList = { BusinessId::DEFAULT },
        .companionCheckResponse = { 1, 2, 3 } };
    syncDeviceStatusReply.companionDeviceKey = COMPANION_DEVICE_KEY;

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "sync companion check failed")).Times(1);

    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply, request->QueryCompanionStatus(syncDeviceStatusReply),
        authenticatedCapabilities);
}

// The enrolled protocol lives in the security agent's DB and is compared there; the check still
// ends the agent-side request, otherwise it would linger in the shared request manager.
HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_DivergedProtocolEndsSecurityAgentRequest, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .companionProtocolIdList = { PROTOCOL_VERSION_2 },
        .businessIdList = { BusinessId::DEFAULT },
        .companionCheckResponse = { 1, 2, 3 } };
    syncDeviceStatusReply.companionDeviceKey = COMPANION_DEVICE_KEY;

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Return(ResultCode::PROTOCOL_NEGOTIATION_FAILED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "sync protocol list diverged")).WillOnce(Return());

    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply, request->QueryCompanionStatus(syncDeviceStatusReply),
        authenticatedCapabilities);
}

// A proofless reply never reaches the security layer, so no divergence verdict can invalidate
// the credential; the round falls through to the legacy empty-proof tolerance.
HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_ProoflessReplySkipsSecureLayer, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .companionProtocolIdList = { PROTOCOL_VERSION_2 },
        .businessIdList = { BusinessId::DEFAULT } };
    syncDeviceStatusReply.companionDeviceKey = COMPANION_DEVICE_KEY;

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);

    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply, request->QueryCompanionStatus(syncDeviceStatusReply),
        authenticatedCapabilities);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, CompleteWithError_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));
    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::SUCCESS));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    SyncDeviceStatus syncDeviceStatus;
    syncDeviceStatus.needSync = true;
    ASSERT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_002, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));
    request->callback_ = nullptr;

    SyncDeviceStatus syncDeviceStatus;
    syncDeviceStatus.needSync = true;
    ASSERT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BuildSyncDeviceStatusRequest_OffersFullProfile, TestSize.Level0)
{
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    LocalDeviceProfile profile = { .protocols = { PROTOCOL_VERSION_2, ProtocolId::VERSION_1 },
        .hostCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH } };
    auto message = request->BuildSyncDeviceStatusRequest(profile, {}, 0);
    EXPECT_EQ(message.hostProtocolIdList, profile.protocols);
    EXPECT_EQ(message.hostCapabilityList, profile.hostCapabilities);
    EXPECT_EQ(message.hostDeviceKey.deviceUserId, HOST_USER_ID);
}

// The peer may announce beyond the local profile, the picker intersects.
HWTEST_F(HostSyncDeviceStatusRequestTest, ValidateReplyParameters_AcceptsSuperset, TestSize.Level0)
{
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto reply = MakeDefaultSyncDeviceStatusReply();
    reply.companionProtocolIdList = { PROTOCOL_VERSION_2, ProtocolId::VERSION_1 };
    reply.companionCapabilityList = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    EXPECT_EQ(request->ValidateReplyParameters(reply), SUCCESS);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, FirstSync_SelectsReplyUserBindingInOneRound, TestSize.Level0)
{
    DeviceKey unknownKey = COMPANION_DEVICE_KEY;
    unknownKey.deviceUserId = INVALID_USER_ID;
    bool succeeded = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        unknownKey, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    LocalDeviceProfile profile = PROFILE;
    profile.protocols = { PROTOCOL_VERSION_2, ProtocolId::VERSION_1 };
    profile.hostCapabilities.push_back(Capability::DELEGATE_AUTH);
    OnMessageReply messageCallback;
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(profile));
    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).Times(1);
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillOnce(Invoke([&](const std::string &, MessageType, const Attributes &attributes, OnMessageReply callback) {
            std::vector<uint16_t> protocols;
            EXPECT_TRUE(attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
            EXPECT_EQ(protocols, ProtocolIdConverter::ToUnderlyingVec(profile.protocols));
            messageCallback = std::move(callback);
            return true;
        }));
    CompanionStatus bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Invoke([&](const HostEndCompanionCheckInput &input, HostEndCompanionCheckOutput &output) {
            EXPECT_EQ(input.templateId, bound.templateId);
            output.companionCapabilityList =
                CapabilityConverter::ToUnderlyingVec(MakeDefaultSyncDeviceStatusReply().companionCapabilityList);
            return SUCCESS;
        }));
    request->OnConnected();
    ASSERT_TRUE(messageCallback);
    Attributes reply;
    EncodeSyncDeviceStatusReply(MakeDefaultSyncDeviceStatusReply(), reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    messageCallback(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
}

// An unoffered announced version on the plaintext outer list fails the structural pre-filter
// before the security layer runs; the rejection fails the round but does not invalidate the
// binding.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_RejectsUnofferedPlaintextProtocol,
    TestSize.Level0)
{
    ResultCode received = SUCCESS;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionProtocolIdList = { PROTOCOL_VERSION_2 };
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, PROTOCOL_NEGOTIATION_FAILED);
}

// A capability growth beyond the enrolled capability list diverges: the template is invalidated but the
// sync round itself still succeeds, so discovery keeps flowing and re-enrollment can proceed.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_CapabilityDivergenceInvalidatesAndSucceeds,
    TestSize.Level0)
{
    ResultCode received = GENERAL_ERROR;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(CAPABILITY_NEGOTIATION_FAILED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync capability list diverged")).Times(1);
    Attributes reply;
    EncodeSyncDeviceStatusReply(MakeDefaultSyncDeviceStatusReply(), reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
}

// The authenticated capability value from the security layer wins over the plaintext
// announcement; the announcement is only the fallback for legacy empty-proof rounds.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_ConsumesAuthenticatedCapabilityValue,
    TestSize.Level0)
{
    bool succeeded = false;
    std::vector<Capability> receivedCapabilities;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded, &receivedCapabilities](ResultCode result, const SyncDeviceStatus &status) {
            succeeded = result == SUCCESS;
            receivedCapabilities = status.companionCapabilityList;
        });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Invoke([](const HostEndCompanionCheckInput &input, HostEndCompanionCheckOutput &output) {
            // Converged value narrower than the plaintext announcement below.
            output.companionCapabilityList = { static_cast<uint16_t>(Capability::TOKEN_AUTH) };
            return SUCCESS;
        }));
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionCapabilityList = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(receivedCapabilities, std::vector<Capability> { Capability::TOKEN_AUTH });
}

// When the security layer returns no authenticated value (legacy empty-proof round), the
// plaintext announcement stays in effect for the in-memory sync result.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_FallsBackToPlainAnnouncement, TestSize.Level0)
{
    bool succeeded = false;
    std::vector<Capability> receivedCapabilities;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded, &receivedCapabilities](ResultCode result, const SyncDeviceStatus &status) {
            succeeded = result == SUCCESS;
            receivedCapabilities = status.companionCapabilityList;
        });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    // Legacy peer: a proofless reply never consults the secure layer; the round is accepted
    // as a legacy empty-proof reply.
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(receivedCapabilities, std::vector<Capability> { Capability::TOKEN_AUTH });
}

HWTEST_F(HostSyncDeviceStatusRequestTest, PeerCheckErrorPreservesBindingAndCancelsCheck, TestSize.Level0)
{
    ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .WillByDefault(Return(std::make_optional(MakeBoundCompanionStatus())));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).Times(0);

    // In every case the binding is preserved and the security agent-side check is cancelled;
    // terminal errors keep their code so the caller aborts the retry.
    const std::pair<ResultCode, ResultCode> peerErrorExpectations[] = {
        { GENERAL_ERROR, PEER_SYNC_FAILED },
        { PROTOCOL_NEGOTIATION_FAILED, PROTOCOL_NEGOTIATION_FAILED },
        { NOT_ENROLLED, NOT_ENROLLED },
    };
    for (auto [peerResult, expectedReport] : peerErrorExpectations) {
        ResultCode received = SUCCESS;
        bool callbackCalled = false;
        auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
            COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
            [&](ResultCode result, const SyncDeviceStatus &status) {
                callbackCalled = true;
                received = result;
                EXPECT_FALSE(status.needSync);
            });
        ASSERT_NE(request, nullptr);
        OnMessageReply callback;
        EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
            .WillOnce(Invoke([&](const std::string &, MessageType, const Attributes &, OnMessageReply reply) {
                callback = std::move(reply);
                return true;
            }));
        EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).Times(1);
        request->OnConnected();
        ASSERT_TRUE(callback);

        // Error-only replies are understood by the baseline decoder without new fields.
        Attributes reply;
        reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(peerResult));
        callback(reply);
        TaskRunnerManager::GetInstance().ExecuteAll();
        EXPECT_TRUE(callbackCalled);
        EXPECT_EQ(received, expectedReport);
        EXPECT_EQ(request->companionDeviceKey_, COMPANION_DEVICE_KEY);
    }
}

// The terminal secure-protocol error passes through verbatim so the caller aborts the retry;
// this path never invalidates the template.
HWTEST_F(HostSyncDeviceStatusRequestTest, PeerCheckSecureProtocolErrorPassesThrough, TestSize.Level0)
{
    ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .WillByDefault(Return(std::make_optional(MakeBoundCompanionStatus())));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).Times(0);

    ResultCode received = SUCCESS;
    bool callbackCalled = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&](ResultCode result, const SyncDeviceStatus &status) {
            callbackCalled = true;
            received = result;
            EXPECT_FALSE(status.needSync);
        });
    ASSERT_NE(request, nullptr);
    OnMessageReply callback;
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillOnce(Invoke([&](const std::string &, MessageType, const Attributes &, OnMessageReply reply) {
            callback = std::move(reply);
            return true;
        }));
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).Times(1);
    request->OnConnected();
    ASSERT_TRUE(callback);

    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(SECURE_PROTOCOL_NOT_SUPPORTED));
    callback(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(received, SECURE_PROTOCOL_NOT_SUPPORTED);
    EXPECT_EQ(request->companionDeviceKey_, COMPANION_DEVICE_KEY);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_TerminalSecureProtocolErrorInvalidatesTemplate,
    TestSize.Level0)
{
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(CompanionStatus {})));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(SECURE_PROTOCOL_NOT_SUPPORTED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "sync companion check failed")).Times(1);
    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(MakeDefaultSyncDeviceStatusReply(),
        request->QueryCompanionStatus(MakeDefaultSyncDeviceStatusReply()), authenticatedCapabilities);
}

// Rule 6 enforced structurally: a proofless reply is never handed to the secure layer, so no
// secure-layer outcome — success or failure — can authenticate the round.
HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_EmptyProofNeverConsultsSecureLayer, TestSize.Level0)
{
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(CompanionStatus {})));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto reply = MakeDefaultSyncDeviceStatusReply();
    reply.companionCheckResponse.clear();
    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(reply, request->QueryCompanionStatus(reply), authenticatedCapabilities);
}

// A legacy empty-proof acceptance under a claimed, not-yet-known user key completes the round
// and learns the announced key for routing only; no failure path reads the cache for
// invalidation authority.
HWTEST_F(HostSyncDeviceStatusRequestTest, LegacyEmptyProofLearnsUserKeyForRoutingOnly, TestSize.Level0)
{
    constexpr int32_t CLAIMED_USER_ID = 201;
    bool succeeded = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey.deviceUserId = CLAIMED_USER_ID;
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, CLAIMED_USER_ID);
}

// Two consecutive unauthenticated rounds never invalidate a binding, even after round 1
// learned the claimed user key into the cache and round 2 fails under the same key.
HWTEST_F(HostSyncDeviceStatusRequestTest, UnauthenticatedRoundsNeverInvalidate, TestSize.Level0)
{
    constexpr int32_t CLAIMED_USER_ID = 201;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillRepeatedly(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto sendReply = [](const std::shared_ptr<HostSyncDeviceStatusRequest> &target) {
        auto message = MakeDefaultSyncDeviceStatusReply();
        message.companionDeviceKey.deviceUserId = CLAIMED_USER_ID;
        message.companionCheckResponse.clear();
        Attributes reply;
        EncodeSyncDeviceStatusReply(message, reply);
        reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
            static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
        reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
        target->HandleSyncDeviceStatusReply(reply);
        TaskRunnerManager::GetInstance().ExecuteAll();
    };

    // Round 1 (cold cache): the empty-proof round is accepted and learns user 201 for routing.
    bool firstSucceeded = false;
    auto first = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&firstSucceeded](ResultCode result, const SyncDeviceStatus &) { firstSucceeded = result == SUCCESS; });
    ASSERT_NE(first, nullptr);
    first->hostProtocolIdList_ = PROFILE.protocols;
    sendReply(first);
    EXPECT_TRUE(firstSucceeded);
    EXPECT_EQ(first->companionDeviceKey_.deviceUserId, CLAIMED_USER_ID);

    // Round 2 (cache washed to user 201): the same unauthenticated failure must still not
    // invalidate the binding.
    auto washedKey = COMPANION_DEVICE_KEY;
    washedKey.deviceUserId = CLAIMED_USER_ID;
    bool secondSucceeded = false;
    auto second = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        washedKey, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&secondSucceeded](ResultCode result, const SyncDeviceStatus &) { secondSucceeded = result == SUCCESS; });
    ASSERT_NE(second, nullptr);
    second->hostProtocolIdList_ = PROFILE.protocols;
    sendReply(second);
    EXPECT_TRUE(secondSucceeded);
}

// Both endpoints may support V1 and V2 while different users enrolled at different versions.
HWTEST_F(HostSyncDeviceStatusRequestTest, UserSwitchUsesReplyBindingAndFullOffer, TestSize.Level0)
{
    constexpr int32_t NEXT_USER_ID = 201;
    UserKey hostUser { HOST_USER_ID, INVALID_SUB_PROFILE_ID };
    auto activeKey = COMPANION_DEVICE_KEY;
    activeKey.deviceUserId = NEXT_USER_ID;
    auto activeBinding = MakeBoundCompanionStatus();
    activeBinding.companionDeviceStatus.deviceKey = activeKey;
    activeBinding.enrolledProtocolId = PROTOCOL_VERSION_2;
    auto profile = PROFILE;
    profile.protocols.push_back(PROTOCOL_VERSION_2);
    bool succeeded = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(hostUser, COMPANION_DEVICE_KEY, CONNECTION_MODE,
        SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    OnMessageReply callback;
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(profile));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillOnce(Invoke([&](const std::string &, MessageType, const Attributes &attributes, OnMessageReply reply) {
            std::vector<uint16_t> protocols;
            EXPECT_TRUE(attributes.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
            EXPECT_EQ(protocols, ProtocolIdConverter::ToUnderlyingVec(profile.protocols));
            callback = std::move(reply);
            return true;
        }));
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(hostUser, activeKey))
        .WillOnce(Return(std::make_optional(activeBinding)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Invoke([&](const HostEndCompanionCheckInput &input, HostEndCompanionCheckOutput &output) {
            EXPECT_EQ(input.templateId, activeBinding.templateId);
            output.companionCapabilityList =
                CapabilityConverter::ToUnderlyingVec(MakeDefaultSyncDeviceStatusReply().companionCapabilityList);
            return SUCCESS;
        }));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    request->OnConnected();
    ASSERT_TRUE(callback);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey = activeKey;
    message.companionProtocolIdList = { PROTOCOL_VERSION_2 };
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(activeKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, activeKey.deviceId);
    callback(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, NEXT_USER_ID);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, DiscoveryDoesNotBorrowAnotherHostUsersBinding, TestSize.Level0)
{
    constexpr int32_t NEXT_HOST_USER_ID = 101;
    UserKey hostUser { NEXT_HOST_USER_ID, INVALID_SUB_PROFILE_ID };
    bool succeeded = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(hostUser, COMPANION_DEVICE_KEY, CONNECTION_MODE,
        SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(hostUser, COMPANION_DEVICE_KEY))
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionProtocolIdList.push_back(PROTOCOL_VERSION_2);
    message.companionCapabilityList.push_back(Capability::DELEGATE_AUTH);
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, UserSwitchToUnboundUserAllowsDiscovery, TestSize.Level0)
{
    constexpr int32_t NEXT_USER_ID = 201;
    UserKey hostUser { HOST_USER_ID, INVALID_SUB_PROFILE_ID };
    auto activeKey = COMPANION_DEVICE_KEY;
    activeKey.deviceUserId = NEXT_USER_ID;
    bool succeeded = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(hostUser, COMPANION_DEVICE_KEY, CONNECTION_MODE,
        SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(hostUser, activeKey)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey = activeKey;
    message.companionProtocolIdList.push_back(PROTOCOL_VERSION_2);
    message.companionCapabilityList.push_back(Capability::DELEGATE_AUTH);
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, NEXT_USER_ID);
}

// A trusted-key empty-proof round keeps the credential: without a verifiable proof the
// ambiguity is resolved in favor of the binding; discovery proceeds and the announced user
// key is learned for routing only.
HWTEST_F(HostSyncDeviceStatusRequestTest, MissingPeerBindingKeepsCredentialButAllowsDiscovery, TestSize.Level0)
{
    bool succeeded = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionCapabilityList.push_back(Capability::DELEGATE_AUTH);
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
}

// A failed proof verification invalidates the binding regardless of which user the reply
// announced; the sync round itself still succeeds and learns the announced key for routing.
HWTEST_F(HostSyncDeviceStatusRequestTest, FailedProofInvalidatesAndRoundStillSucceeds, TestSize.Level0)
{
    constexpr int32_t NEXT_USER_ID = 201;
    ResultCode received = GENERAL_ERROR;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(GENERAL_ERROR));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync companion check failed")).Times(1);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey.deviceUserId = NEXT_USER_ID;
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, NEXT_USER_ID);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 100);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_SYNC_DEVICE_STATUS_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);

    EXPECT_FALSE(result);
}

// The sync round must not bring its own peer online, or the request would end up waiting on the
// very round it is about to start.
HWTEST_F(HostSyncDeviceStatusRequestTest, RequireSyncedDevice_IsFalse, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));

    EXPECT_FALSE(request->RequireSyncedDevice());
}

// An announced list that is empty or has no overlap with the local offer stops the round with
// the specific negotiation code instead of falling through to the security layer.
HWTEST_F(HostSyncDeviceStatusRequestTest, ValidateReplyParameters_RejectsEmptyIntersection, TestSize.Level0)
{
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto reply = MakeDefaultSyncDeviceStatusReply();
    reply.companionProtocolIdList.clear();
    EXPECT_EQ(request->ValidateReplyParameters(reply), PROTOCOL_NEGOTIATION_FAILED);
    reply.companionProtocolIdList = { PROTOCOL_VERSION_2 };
    EXPECT_EQ(request->ValidateReplyParameters(reply), PROTOCOL_NEGOTIATION_FAILED);
    reply.companionProtocolIdList = PROFILE.protocols;
    EXPECT_EQ(request->ValidateReplyParameters(reply), SUCCESS);
}

// A divergence found after the proof verified is authenticated and invalidates the binding
// regardless of which user key the discovery cache holds; the round itself still succeeds.
HWTEST_F(HostSyncDeviceStatusRequestTest, DivergedListWithUntrustedUserKeyStillInvalidates, TestSize.Level0)
{
    constexpr int32_t CLAIMED_USER_ID = 201;
    ResultCode received = SUCCESS;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(PROTOCOL_NEGOTIATION_FAILED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "sync protocol list diverged")).Times(1);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey.deviceUserId = CLAIMED_USER_ID;
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, CLAIMED_USER_ID);
}

// A secure protocol the Rust layer cannot consume is rejected (20013) and invalidates the
// binding; the sync round itself still succeeds.
HWTEST_F(HostSyncDeviceStatusRequestTest, FutureSecureProtocolInvalidatesTemplate, TestSize.Level0)
{
    ResultCode received = GENERAL_ERROR;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(SECURE_PROTOCOL_NOT_SUPPORTED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync companion check failed")).Times(1);
    Attributes reply;
    EncodeSyncDeviceStatusReply(MakeDefaultSyncDeviceStatusReply(), reply);
    reply.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, 2); // future version
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
}

// An authenticated enrolled-protocol divergence invalidates with the divergence-specific reason;
// the sync round itself still succeeds.
HWTEST_F(HostSyncDeviceStatusRequestTest, DivergedEnrolledProtocolInvalidatesWithReason, TestSize.Level0)
{
    ResultCode received = GENERAL_ERROR;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->hostProtocolIdList_ = PROFILE.protocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(PROTOCOL_NEGOTIATION_FAILED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync protocol list diverged")).Times(1);
    Attributes reply;
    EncodeSyncDeviceStatusReply(MakeDefaultSyncDeviceStatusReply(), reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
    request->HandleSyncDeviceStatusReply(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
