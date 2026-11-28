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
#include "binding_signature_message.h"
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
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };
constexpr ConnectionMode CONNECTION_MODE = ConnectionMode::BACKGROUND;
const LocalDeviceProfile PROFILE = { .hostProtocols = { ProtocolId::VERSION_1 },
    .hostCapabilities = { Capability::TOKEN_AUTH },
    .companionCapabilities = { Capability::TOKEN_AUTH } };

SyncDeviceStatusReply MakeDefaultSyncDeviceStatusReply()
{
    return {
        .result = ResultCode::SUCCESS,
        .companionProofProtocolIdList = { ProtocolId::VERSION_1 },
        .companionCapabilityList = { Capability::TOKEN_AUTH },
        .businessIdList = { BusinessId::DEFAULT },
        .secureProtocolId = SecureProtocolId::DEFAULT,
        .companionDeviceKey = COMPANION_DEVICE_KEY,
        .deviceUserName = "test_user_name",
        .companionCheckResponse = { 1, 2, 3 },
        .companionSupportedProtocolIdList = { ProtocolId::VERSION_1 },
    };
}

// Wire shape of a peer predating ATTR_CDA_SA_COMPANION_SUPPORTED_PROTOCOL_ID_LIST: the current
// encoder always carries the field, so the old format is assembled by hand, without the key.
Attributes EncodeOldPeerSyncDeviceStatusReply(const SyncDeviceStatusReply &reply)
{
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
    std::vector<uint16_t> protocolIdList;
    for (const auto &protocol : reply.companionProofProtocolIdList) {
        protocolIdList.push_back(static_cast<uint16_t>(protocol));
    }
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocolIdList);
    std::vector<uint16_t> capabilityList;
    for (const auto &capability : reply.companionCapabilityList) {
        capabilityList.push_back(static_cast<uint16_t>(capability));
    }
    attributes.SetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, capabilityList);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, reply.companionDeviceKey.deviceUserId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID,
        reply.companionDeviceKey.deviceSubProfileId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(reply.companionDeviceKey.idType));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, reply.companionDeviceKey.deviceId);
    attributes.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID,
        static_cast<uint16_t>(reply.secureProtocolId));
    attributes.SetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, reply.deviceUserName);
    attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, reply.companionCheckResponse);
    return attributes;
}

CompanionStatus MakeBoundCompanionStatus()
{
    CompanionStatus bound;
    bound.templateId = HOST_USER_ID;
    bound.hostUserKey = UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID };
    bound.isValid = true;
    bound.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    bound.enrolledProtocolId = ProtocolId::VERSION_1;
    return bound;
}

CompanionStatus MakeV2CompanionStatus()
{
    CompanionStatus status = {};
    status.templateId = 1;
    status.hostUserKey = UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID };
    status.isValid = true;
    status.enrolledProtocolId = ProtocolId::VERSION_2;
    status.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    return status;
}

Attributes MakeReplyAttributes(const SyncDeviceStatusReply &replyData)
{
    Attributes reply;
    EncodeSyncDeviceStatusReply(replyData, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(replyData.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, replyData.companionDeviceKey.deviceId);
    return reply;
}

LocalDeviceProfile MakeDualProtocolProfile()
{
    auto profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    return profile;
}

void DeliverSyncReply(const OnMessageReply &callback, const SyncDeviceStatusReply &replyData)
{
    ASSERT_TRUE(callback);
    callback(MakeReplyAttributes(replyData));
    TaskRunnerManager::GetInstance().ExecuteAll();
}

void SetCompanionSrcIdentifier(Attributes &reply)
{
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(COMPANION_DEVICE_KEY.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, COMPANION_DEVICE_KEY.deviceId);
}

void ReplyBindingSignatureChallenge(OnMessageReply &onReply, ResultCode result, const UserKey &companionUserKey,
    const std::vector<uint8_t> &challenge)
{
    GetBindingSignatureChallengeReply challengeReply = {};
    challengeReply.result = result;
    challengeReply.companionUserKey = companionUserKey;
    challengeReply.challenge = challenge;
    Attributes replyAttributes;
    EncodeGetBindingSignatureChallengeReply(challengeReply, replyAttributes);
    onReply(replyAttributes);
}

std::shared_ptr<HostSyncDeviceStatusRequest> MakeDefaultRequest(SyncDeviceStatusCallback callback)
{
    return std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        COMPANION_DEVICE_KEY, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH, std::move(callback));
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
    // Make bindings visible to the host-scoped FilterCompanionStatus scan with the same
    // narrowing the real manager applies: host user, physical peer device, validity, protocol.
    void MakeStatusesVisible(std::vector<CompanionStatus> statuses)
    {
        ON_CALL(mockCompanionManager_, FilterCompanionStatus(_, _, _))
            .WillByDefault(Invoke([statuses](const UserKey &hostUserKey, const PhysicalDeviceKey &physicalKey,
                                      std::optional<ProtocolId> protocolId) {
                std::vector<CompanionStatus> matches;
                for (const auto &status : statuses) {
                    if (status.hostUserKey != hostUserKey ||
                        status.companionDeviceStatus.deviceKey.AsPhysical() != physicalKey || !status.isValid) {
                        continue;
                    }
                    if (protocolId.has_value() && status.enrolledProtocolId != *protocolId) {
                        continue;
                    }
                    matches.push_back(status);
                }
                return matches;
            }));
    }

    // V2 candidate binding plus the challenge roundtrip/signature plumbing shared by V2 sync tests.
    void AttachV2BindingSignatureMocks(const std::vector<uint8_t> &challenge, const std::vector<uint8_t> &signature,
        bool &challengeResolveSucceeds, std::vector<uint8_t> &sentChallenge, std::vector<uint8_t> &sentSignature,
        int32_t &sentCompanionUserId)
    {
        CompanionStatus v2Candidate = MakeV2CompanionStatus();
        MakeStatusesVisible({ v2Candidate });
        // identity resolution is the keyed GetCompanionStatus lookup
        ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
            .WillByDefault(Invoke([v2Candidate](const UserKey &hostUserKey, const DeviceKey &deviceKey) {
                return (v2Candidate.hostUserKey == hostUserKey &&
                           v2Candidate.companionDeviceStatus.deviceKey == deviceKey)
                    ? std::make_optional(v2Candidate)
                    : std::nullopt;
            }));

        ON_CALL(mockSecurityAgent_, HostBindingSign(_, _))
            .WillByDefault(Invoke([&signature](const HostBindingSignInput &, HostBindingSignOutput &output) {
                output.signature = signature;
                return ResultCode::SUCCESS;
            }));

        // clang-format off
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
            .WillByDefault(
            Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply &&onReply) {
                if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                    ReplyBindingSignatureChallenge(onReply,
                        challengeResolveSucceeds ? ResultCode::SUCCESS : ResultCode::GENERAL_ERROR,
                        UserKey { COMPANION_DEVICE_KEY.deviceUserId, COMPANION_DEVICE_KEY.deviceSubProfileId },
                        challenge);
                    return true;
                }
                EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
                request.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, sentChallenge);
                request.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE, sentSignature);
                request.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, sentCompanionUserId);
                return true;
            }));
        // clang-format on
    }

    void ExpectUserSwitchChallengeAndSync(int32_t nextUserId, const LocalDeviceProfile &profile,
        const std::vector<uint8_t> &challenge, const std::vector<uint8_t> &signature, OnMessageReply &callback)
    {
        EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
            .WillOnce(Invoke(
                [&, nextUserId](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
                    EXPECT_EQ(MessageType::GET_BINDING_SIGNATURE_CHALLENGE, msgType);
                    ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                        UserKey { nextUserId, INVALID_SUB_PROFILE_ID }, challenge);
                    return true;
                }))
            .WillOnce(Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply reply) {
                EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
                std::vector<uint16_t> protocols;
                EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
                EXPECT_EQ(protocols, ProtocolIdConverter::ToUnderlyingVec(profile.hostProtocols));
                std::vector<uint8_t> sentChallenge;
                std::vector<uint8_t> sentSignature;
                EXPECT_TRUE(
                    request.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, sentChallenge));
                EXPECT_TRUE(request.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE, sentSignature));
                EXPECT_EQ(challenge, sentChallenge);
                EXPECT_EQ(signature, sentSignature);
                callback = std::move(reply);
                return true;
            }));
    }

    void ExpectChallengeFailureDowngrade(OnMessageReply &downgradeCallback)
    {
        // clang-format off
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
            .WillByDefault(
            Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply &&onReply) {
                if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                    GetBindingSignatureChallengeReply challengeReply = {};
                    challengeReply.result = ResultCode::GENERAL_ERROR;
                    Attributes replyAttributes;
                    EncodeGetBindingSignatureChallengeReply(challengeReply, replyAttributes);
                    onReply(replyAttributes);
                    return true;
                }
                EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
                std::vector<uint16_t> protocols;
                EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
                EXPECT_EQ(protocols,
                    ProtocolIdConverter::ToUnderlyingVec(std::vector<ProtocolId> { ProtocolId::VERSION_1 }));
                EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE));
                EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE));
                downgradeCallback = std::move(onReply);
                return true;
            }));
        // clang-format on
    }

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
    auto request = MakeDefaultRequest(std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    // two reads on the discovery path: request composition and the send itself
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).Times(2).WillRepeatedly(Return(PROFILE));
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
    auto request = MakeDefaultRequest(std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::FAIL));

    request->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, SendSyncDeviceStatusRequest_001, TestSize.Level0)
{
    // Since the V2 binding-signature gate the send failure is settled asynchronously: the call returns
    // true and the COMMUNICATION_ERROR reaches the callback via the resident task runner.
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request = MakeDefaultRequest(std::move(callback));

    // two reads on the discovery path: request composition and the send itself
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).Times(2).WillRepeatedly(Return(PROFILE));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_001, TestSize.Level0)
{
    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request = MakeDefaultRequest(std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    Attributes reply = MakeReplyAttributes(syncDeviceStatusReply);

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());

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
    auto request = MakeDefaultRequest(std::move(callback));

    Attributes reply;
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_003, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    // Generic peer failures collapse into PEER_SYNC_FAILED; terminal errors
    // (PROTOCOL_NEGOTIATION_FAILED, SECURE_PROTOCOL_NOT_SUPPORTED, NOT_ENROLLED) pass through
    // verbatim so the caller aborts the retry. NOT_ENROLLED and BINDING_SIGNATURE_VERIFY_FAILED
    // additionally invalidate the round's authenticated credential (none on unsigned rounds).
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::PEER_SYNC_FAILED) {
            *errorCalled = true;
        }
    };
    auto request = MakeDefaultRequest(std::move(callback));
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    syncDeviceStatusReply.result = ResultCode::GENERAL_ERROR;
    Attributes reply = MakeReplyAttributes(syncDeviceStatusReply);

    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());

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
    auto request = MakeDefaultRequest(std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    Attributes reply = MakeReplyAttributes(syncDeviceStatusReply);

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request->cancelCompanionCheckGuard_ = nullptr;
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::GENERAL_ERROR,
        .businessIdList = { BusinessId::DEFAULT } };
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply,
        request->QueryCompanionStatus(syncDeviceStatusReply.companionDeviceKey.AsUserKey()), authenticatedCapabilities);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_002, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .businessIdList = { BusinessId::DEFAULT } };
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply,
        request->QueryCompanionStatus(syncDeviceStatusReply.companionDeviceKey.AsUserKey()), authenticatedCapabilities);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_003, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .businessIdList = { BusinessId::DEFAULT },
        .companionCheckResponse = { 1, 2, 3 } };
    syncDeviceStatusReply.companionDeviceKey = COMPANION_DEVICE_KEY;

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "sync companion check failed")).Times(1);

    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply,
        request->QueryCompanionStatus(syncDeviceStatusReply.companionDeviceKey.AsUserKey()), authenticatedCapabilities);
}

// The enrolled protocol lives in the security agent's DB and is compared there; the check still
// ends the agent-side request, otherwise it would linger in the shared request manager.
HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_DivergedProtocolEndsSecurityAgentRequest, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .companionProofProtocolIdList = { ProtocolId::VERSION_2 },
        .businessIdList = { BusinessId::DEFAULT },
        .companionCheckResponse = { 1, 2, 3 } };
    syncDeviceStatusReply.companionDeviceKey = COMPANION_DEVICE_KEY;

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Return(ResultCode::PROTOCOL_NEGOTIATION_FAILED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "sync protocol list diverged")).WillOnce(Return());

    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply,
        request->QueryCompanionStatus(syncDeviceStatusReply.companionDeviceKey.AsUserKey()), authenticatedCapabilities);
}

// A proofless reply never reaches the security layer, so no divergence verdict can authenticate
// the round; the credential is unconditionally invalidated, V1 and V2 alike.
HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_ProoflessReplyInvalidatesCredential, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .companionProofProtocolIdList = { ProtocolId::VERSION_2 },
        .businessIdList = { BusinessId::DEFAULT } };
    syncDeviceStatusReply.companionDeviceKey = COMPANION_DEVICE_KEY;

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "bound peer returned no proof")).Times(1);

    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(syncDeviceStatusReply,
        request->QueryCompanionStatus(syncDeviceStatusReply.companionDeviceKey.AsUserKey()), authenticatedCapabilities);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, CompleteWithError_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));
    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::SUCCESS));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    SyncDeviceStatus syncDeviceStatus;
    syncDeviceStatus.needSync = true;
    ASSERT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_002, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));
    request->callback_ = nullptr;

    SyncDeviceStatus syncDeviceStatus;
    syncDeviceStatus.needSync = true;
    ASSERT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BuildSyncDeviceStatusRequest_OffersFullProfile, TestSize.Level0)
{
    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    LocalDeviceProfile profile = { .hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 },
        .hostCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH } };
    auto message = request->BuildSyncDeviceStatusRequest(profile, {}, 0);
    EXPECT_EQ(message.hostProtocolIdList, profile.hostProtocols);
    EXPECT_EQ(message.hostCapabilityList, profile.hostCapabilities);
    EXPECT_EQ(message.hostDeviceKey.deviceUserId, HOST_USER_ID);
}

// The peer may announce beyond the local profile, the picker intersects.
HWTEST_F(HostSyncDeviceStatusRequestTest, ValidateReplyParameters_AcceptsSuperset, TestSize.Level0)
{
    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto reply = MakeDefaultSyncDeviceStatusReply();
    reply.companionProofProtocolIdList = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    reply.companionSupportedProtocolIdList = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    reply.companionCapabilityList = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    EXPECT_EQ(request->ValidateReplyParameters(reply), SUCCESS);
}

// A first sync against a device holding only a valid V1 binding skips the challenge roundtrip
// entirely — there is nothing to sign, and no resolved identity can move the offer away from
// {VERSION_1} (the legacy peer's Rust would whole-list-reject a wider offer). The round dispatches
// unprotected in a single message.
HWTEST_F(HostSyncDeviceStatusRequestTest, FirstSync_SelectsReplyUserBindingInOneRound, TestSize.Level0)
{
    DeviceKey unknownKey = COMPANION_DEVICE_KEY;
    unknownKey.deviceUserId = INVALID_USER_ID;
    CompanionStatus bound = MakeBoundCompanionStatus();
    MakeStatusesVisible({ bound });

    auto profile = MakeDualProtocolProfile();
    profile.hostCapabilities.push_back(Capability::DELEGATE_AUTH);
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    OnMessageReply messageCallback;
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillOnce(Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply reply) {
            EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
            std::vector<uint16_t> protocols;
            EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
            EXPECT_EQ(protocols, std::vector<uint16_t> { static_cast<uint16_t>(ProtocolId::VERSION_1) });
            EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE));
            EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE));
            messageCallback = std::move(reply);
            return true;
        }));
    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).Times(1);
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    // valid-binding gate scan, then the V1-only shortcut scan; no challenge round follows
    EXPECT_CALL(mockCompanionManager_, FilterCompanionStatus(_, _, _)).Times(2);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Invoke([&](const HostEndCompanionCheckInput &input, HostEndCompanionCheckOutput &output) {
            EXPECT_EQ(input.templateId, bound.templateId);
            output.companionCapabilityList =
                CapabilityConverter::ToUnderlyingVec(MakeDefaultSyncDeviceStatusReply().companionCapabilityList);
            return SUCCESS;
        }));

    bool succeeded = false;
    std::vector<Capability> receivedCapabilities;
    uint16_t selectedProtocolId = 0;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        unknownKey, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&](ResultCode result, const SyncDeviceStatus &status) {
            succeeded = result == SUCCESS;
            receivedCapabilities = status.companionCapabilityList;
            selectedProtocolId = status.selectedProtocolId;
        });
    ASSERT_NE(request, nullptr);
    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    DeliverSyncReply(messageCallback, MakeDefaultSyncDeviceStatusReply());
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(receivedCapabilities, MakeDefaultSyncDeviceStatusReply().companionCapabilityList);
    EXPECT_EQ(selectedProtocolId, static_cast<uint16_t>(ProtocolId::VERSION_1));
}

// An unoffered announced version on the plaintext outer list fails the structural pre-filter
// before the security layer runs; the rejection fails the round but does not invalidate the
// binding.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_RejectsUnofferedPlaintextProtocol,
    TestSize.Level0)
{
    ResultCode received = SUCCESS;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionProofProtocolIdList = { ProtocolId::VERSION_2 };
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, PROTOCOL_NEGOTIATION_FAILED);
}

// A capability growth beyond the enrolled capability list diverges: the template is invalidated but the
// sync round itself still succeeds, so discovery keeps flowing and re-enrollment can proceed.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_CapabilityDivergenceInvalidatesAndSucceeds,
    TestSize.Level0)
{
    ResultCode received = GENERAL_ERROR;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(CAPABILITY_NEGOTIATION_FAILED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync capability list diverged")).Times(1);
    Attributes reply;
    EncodeSyncDeviceStatusReply(MakeDefaultSyncDeviceStatusReply(), reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
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
    auto request =
        MakeDefaultRequest([&succeeded, &receivedCapabilities](ResultCode result, const SyncDeviceStatus &status) {
            succeeded = result == SUCCESS;
            receivedCapabilities = status.companionCapabilityList;
        });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
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
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(receivedCapabilities, std::vector<Capability> { Capability::TOKEN_AUTH });
}

// When the round cannot be verified (empty proof under a live credential), the credential is
// invalidated but the plaintext announcement still feeds the in-memory sync result: an empty
// capability table must never enter the cache.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_FallsBackToPlainAnnouncement, TestSize.Level0)
{
    bool succeeded = false;
    std::vector<Capability> receivedCapabilities;
    auto request =
        MakeDefaultRequest([&succeeded, &receivedCapabilities](ResultCode result, const SyncDeviceStatus &status) {
            succeeded = result == SUCCESS;
            receivedCapabilities = status.companionCapabilityList;
        });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "bound peer returned no proof")).Times(1);
    // A proofless reply never consults the secure layer; the round is accepted but unverifiable.
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
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
    // terminal errors keep their code so the caller aborts the retry. NOT_ENROLLED and a
    // binding-signature rejection invalidate the credential and have their own tests below.
    const std::pair<ResultCode, ResultCode> peerErrorExpectations[] = {
        { GENERAL_ERROR, PEER_SYNC_FAILED },
        { PROTOCOL_NEGOTIATION_FAILED, PROTOCOL_NEGOTIATION_FAILED },
    };
    for (auto [peerResult, expectedReport] : peerErrorExpectations) {
        ResultCode received = SUCCESS;
        bool callbackCalled = false;
        auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
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

// A binding-signature rejection names the peer's current user: the local credential for that
// user is invalidated, and the round still completes with the error.
HWTEST_F(HostSyncDeviceStatusRequestTest, PeerBindingSignatureRejectionInvalidatesCredential, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    const std::vector<uint8_t> signature(64, 0xEE);
    CompanionStatus v2Bound = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Bound });
    ON_CALL(mockSecurityAgent_, HostBindingSign(_, _))
        .WillByDefault(Invoke([&signature](const HostBindingSignInput &, HostBindingSignOutput &output) {
            output.signature = signature;
            return ResultCode::SUCCESS;
        }));
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(Invoke([&](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
            if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                    UserKey { COMPANION_DEVICE_KEY.deviceUserId, COMPANION_DEVICE_KEY.deviceSubProfileId }, challenge);
                return true;
            }
            return true;
        }));

    ResultCode received = SUCCESS;
    bool callbackCalled = false;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        callbackCalled = true;
        received = result;
        EXPECT_FALSE(status.needSync);
    });
    ASSERT_NE(request, nullptr);
    // The rejection reply carries the peer user identity: invalidation settles that user's
    // credential. Two lookups happen: the challenge-round identity match and the invalidation.
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .Times(2)
        .WillRepeatedly(Return(std::make_optional(v2Bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(v2Bound.templateId, "peer rejected binding signature"))
        .Times(1);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).Times(1);

    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).Times(0);
    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(BINDING_SIGNATURE_VERIFY_FAILED));
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, COMPANION_DEVICE_KEY.deviceUserId);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, COMPANION_DEVICE_KEY.deviceSubProfileId);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(received, BINDING_SIGNATURE_VERIFY_FAILED);
}

// A NOT_ENROLLED reply on a signed round is the peer's deterministic refusal naming its current
// user: the credential is invalidated with the same single-user settlement as a signature rejection,
// and the round fails with the peer's code — no in-request redo send.
HWTEST_F(HostSyncDeviceStatusRequestTest, PeerNotEnrolledRejectionInvalidatesCredential, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    const std::vector<uint8_t> signature(64, 0xEE);
    CompanionStatus v2Bound = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Bound });
    ON_CALL(mockSecurityAgent_, HostBindingSign(_, _))
        .WillByDefault(Invoke([&signature](const HostBindingSignInput &, HostBindingSignOutput &output) {
            output.signature = signature;
            return ResultCode::SUCCESS;
        }));
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(Invoke([&](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
            if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                    UserKey { COMPANION_DEVICE_KEY.deviceUserId, COMPANION_DEVICE_KEY.deviceSubProfileId }, challenge);
                return true;
            }
            return true;
        }));

    ResultCode received = SUCCESS;
    bool callbackCalled = false;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        callbackCalled = true;
        received = result;
        EXPECT_FALSE(status.needSync);
    });
    ASSERT_NE(request, nullptr);
    // Two lookups happen: the challenge-round identity match and the invalidation.
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .Times(2)
        .WillRepeatedly(Return(std::make_optional(v2Bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(v2Bound.templateId, "peer rejected binding signature"))
        .Times(1);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).Times(1);

    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).Times(0);
    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(NOT_ENROLLED));
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, COMPANION_DEVICE_KEY.deviceUserId);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, COMPANION_DEVICE_KEY.deviceSubProfileId);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(received, NOT_ENROLLED);
}

// A refusal that carries no peer identity cannot locate a user: nothing is invalidated and the
// round fails with the peer's code (legacy peers and early error paths reply without identity).
HWTEST_F(HostSyncDeviceStatusRequestTest, PeerNotEnrolledReplyWithoutIdentityKeepsCredential, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    const std::vector<uint8_t> signature(64, 0xEE);
    CompanionStatus v2Bound = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Bound });
    ON_CALL(mockSecurityAgent_, HostBindingSign(_, _))
        .WillByDefault(Invoke([&signature](const HostBindingSignInput &, HostBindingSignOutput &output) {
            output.signature = signature;
            return ResultCode::SUCCESS;
        }));
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(Invoke([&](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
            if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                    UserKey { COMPANION_DEVICE_KEY.deviceUserId, COMPANION_DEVICE_KEY.deviceSubProfileId }, challenge);
                return true;
            }
            return true;
        }));

    ResultCode received = SUCCESS;
    bool callbackCalled = false;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        callbackCalled = true;
        received = result;
        EXPECT_FALSE(status.needSync);
    });
    ASSERT_NE(request, nullptr);
    // Only the challenge-round identity match happens; no identity means no invalidation lookup.
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(v2Bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).Times(1);

    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).Times(0);
    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(NOT_ENROLLED));
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(received, NOT_ENROLLED);
}

// A refusal naming a user with no local credential invalidates nothing: invalidation only ever
// settles the named user's row, never the round's credential.
HWTEST_F(HostSyncDeviceStatusRequestTest, PeerNotEnrolledReplyWithForeignIdentityKeepsCredential, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    const std::vector<uint8_t> signature(64, 0xEE);
    CompanionStatus v2Bound = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Bound });
    ON_CALL(mockSecurityAgent_, HostBindingSign(_, _))
        .WillByDefault(Invoke([&signature](const HostBindingSignInput &, HostBindingSignOutput &output) {
            output.signature = signature;
            return ResultCode::SUCCESS;
        }));
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(Invoke([&](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
            if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                    UserKey { COMPANION_DEVICE_KEY.deviceUserId, COMPANION_DEVICE_KEY.deviceSubProfileId }, challenge);
                return true;
            }
            return true;
        }));

    ResultCode received = SUCCESS;
    bool callbackCalled = false;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        callbackCalled = true;
        received = result;
        EXPECT_FALSE(status.needSync);
    });
    ASSERT_NE(request, nullptr);
    // The challenge-round match finds the credential; the invalidation lookup for the named
    // foreign user finds nothing, so the credential survives.
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(v2Bound)))
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).Times(1);

    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).Times(0);
    Attributes reply;
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(NOT_ENROLLED));
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, COMPANION_DEVICE_KEY.deviceUserId + 1);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, COMPANION_DEVICE_KEY.deviceSubProfileId);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(received, NOT_ENROLLED);
}

// A NOT_ENROLLED reply is terminal on any round: the round fails with the peer's code and no
// in-request redo is sent. On an unsigned round there is no authenticated identity, so nothing
// is invalidated; the signed-round invalidation case has its own test above.
HWTEST_F(HostSyncDeviceStatusRequestTest, NotEnrolledReplyFailsRoundWithoutRedo, TestSize.Level0)
{
    ResultCode received = SUCCESS;
    bool callbackCalled = false;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        callbackCalled = true;
        received = result;
        EXPECT_FALSE(status.needSync);
    });
    ASSERT_NE(request, nullptr);
    std::vector<OnMessageReply> syncReplies;
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .Times(1)
        .WillRepeatedly(Invoke([&](const std::string &, MessageType, const Attributes &, OnMessageReply reply) {
            syncReplies.push_back(std::move(reply));
            return true;
        }));
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).Times(1);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);

    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(syncReplies.size(), 1U); // no credentials: unsigned discovery round

    Attributes notEnrolled;
    notEnrolled.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(ResultCode::NOT_ENROLLED));
    syncReplies[0](notEnrolled); // terminal: round fails, no redo send
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(received, ResultCode::NOT_ENROLLED);
    EXPECT_EQ(syncReplies.size(), 1U);
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
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
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
    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(CompanionStatus {})));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(SECURE_PROTOCOL_NOT_SUPPORTED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "sync companion check failed")).Times(1);
    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(MakeDefaultSyncDeviceStatusReply(),
        request->QueryCompanionStatus(MakeDefaultSyncDeviceStatusReply().companionDeviceKey.AsUserKey()),
        authenticatedCapabilities);
}

// Rule 6 enforced structurally: a proofless reply is never handed to the secure layer, so no
// secure-layer outcome — success or failure — can authenticate the round; it invalidates instead.
HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_EmptyProofNeverConsultsSecureLayer, TestSize.Level0)
{
    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(CompanionStatus {})));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "bound peer returned no proof")).Times(1);
    auto reply = MakeDefaultSyncDeviceStatusReply();
    reply.companionCheckResponse.clear();
    std::vector<Capability> authenticatedCapabilities;
    request->EndCompanionCheck(reply, request->QueryCompanionStatus(reply.companionDeviceKey.AsUserKey()),
        authenticatedCapabilities);
}

// An empty-proof round under a claimed, not-yet-known user key completes the round, learns the
// announced key for routing, and invalidates the credential the claimed identity resolves to:
// an unverifiable round is never tolerated as proof of a live binding.
HWTEST_F(HostSyncDeviceStatusRequestTest, EmptyProofLearnsUserKeyAndInvalidatesCredential, TestSize.Level0)
{
    constexpr int32_t CLAIMED_USER_ID = 201;
    bool succeeded = false;
    auto request = MakeDefaultRequest(
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "bound peer returned no proof")).Times(1);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey.deviceUserId = CLAIMED_USER_ID;
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, CLAIMED_USER_ID);
}

// Two consecutive unauthenticated rounds each invalidate the credential their claimed identity
// resolves to; the rounds themselves still complete so discovery keeps flowing.
HWTEST_F(HostSyncDeviceStatusRequestTest, UnauthenticatedRoundsInvalidateEachRound, TestSize.Level0)
{
    constexpr int32_t CLAIMED_USER_ID = 201;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillRepeatedly(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "bound peer returned no proof")).Times(2);
    auto sendReply = [](const std::shared_ptr<HostSyncDeviceStatusRequest> &target) {
        auto message = MakeDefaultSyncDeviceStatusReply();
        message.companionDeviceKey.deviceUserId = CLAIMED_USER_ID;
        message.companionCheckResponse.clear();
        Attributes reply;
        EncodeSyncDeviceStatusReply(message, reply);
        SetCompanionSrcIdentifier(reply);
        target->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
        TaskRunnerManager::GetInstance().ExecuteAll();
    };

    bool firstSucceeded = false;
    auto first = MakeDefaultRequest(
        [&firstSucceeded](ResultCode result, const SyncDeviceStatus &) { firstSucceeded = result == SUCCESS; });
    ASSERT_NE(first, nullptr);
    first->sentProtocolIdList_ = PROFILE.hostProtocols;
    sendReply(first);
    EXPECT_TRUE(firstSucceeded);
    EXPECT_EQ(first->companionDeviceKey_.deviceUserId, CLAIMED_USER_ID);

    auto washedKey = COMPANION_DEVICE_KEY;
    washedKey.deviceUserId = CLAIMED_USER_ID;
    bool secondSucceeded = false;
    auto second = std::make_shared<HostSyncDeviceStatusRequest>(UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID },
        washedKey, CONNECTION_MODE, SyncTriggerReason::EXTERNAL_REFRESH,
        [&secondSucceeded](ResultCode result, const SyncDeviceStatus &) { secondSucceeded = result == SUCCESS; });
    ASSERT_NE(second, nullptr);
    second->sentProtocolIdList_ = PROFILE.hostProtocols;
    sendReply(second);
    EXPECT_TRUE(secondSucceeded);
}

// Both endpoints may support V1 and V2 while different users enrolled at different versions: the
// resolved identity maps to the V2 credential, so the round is signed and restores the full offer.
HWTEST_F(HostSyncDeviceStatusRequestTest, UserSwitchUsesReplyBindingAndFullOffer, TestSize.Level0)
{
    constexpr int32_t NEXT_USER_ID = 201;
    UserKey hostUser { HOST_USER_ID, INVALID_SUB_PROFILE_ID };
    auto activeKey = COMPANION_DEVICE_KEY;
    activeKey.deviceUserId = NEXT_USER_ID;
    auto activeBinding = MakeBoundCompanionStatus();
    activeBinding.companionDeviceStatus.deviceKey = activeKey;
    activeBinding.enrolledProtocolId = ProtocolId::VERSION_2;
    auto profile = PROFILE;
    profile.hostProtocols.push_back(ProtocolId::VERSION_2);
    MakeStatusesVisible({ activeBinding });
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    const std::vector<uint8_t> signature(64, 0xEE);
    ON_CALL(mockSecurityAgent_, HostBindingSign(_, _))
        .WillByDefault(Invoke([&signature](const HostBindingSignInput &, HostBindingSignOutput &output) {
            output.signature = signature;
            return ResultCode::SUCCESS;
        }));

    OnMessageReply callback;
    ExpectUserSwitchChallengeAndSync(NEXT_USER_ID, profile, challenge, signature, callback);
    // valid-binding gate scan and V2-only gate scan; identity resolution and the reply binding
    // lookup both go through the keyed GetCompanionStatus
    EXPECT_CALL(mockCompanionManager_, FilterCompanionStatus(_, _, _)).Times(2);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(hostUser, activeKey))
        .WillRepeatedly(Return(std::make_optional(activeBinding)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Invoke([&](const HostEndCompanionCheckInput &input, HostEndCompanionCheckOutput &output) {
            EXPECT_EQ(input.templateId, activeBinding.templateId);
            output.companionCapabilityList =
                CapabilityConverter::ToUnderlyingVec(MakeDefaultSyncDeviceStatusReply().companionCapabilityList);
            return SUCCESS;
        }));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);

    bool succeeded = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(hostUser, COMPANION_DEVICE_KEY, CONNECTION_MODE,
        SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey = activeKey;
    message.companionProofProtocolIdList = { ProtocolId::VERSION_2 };
    message.companionSupportedProtocolIdList = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    DeliverSyncReply(callback, message);
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
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    EXPECT_CALL(mockCompanionManager_, FilterCompanionStatus(_, _, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(hostUser, COMPANION_DEVICE_KEY))
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionProofProtocolIdList.push_back(ProtocolId::VERSION_2);
    message.companionSupportedProtocolIdList = message.companionProofProtocolIdList;
    message.companionCapabilityList.push_back(Capability::DELEGATE_AUTH);
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
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
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    EXPECT_CALL(mockCompanionManager_, FilterCompanionStatus(_, _, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(hostUser, activeKey)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey = activeKey;
    message.companionProofProtocolIdList.push_back(ProtocolId::VERSION_2);
    message.companionSupportedProtocolIdList = message.companionProofProtocolIdList;
    message.companionCapabilityList.push_back(Capability::DELEGATE_AUTH);
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, NEXT_USER_ID);
}

// An empty-proof round under a live credential invalidates it (the round is unverifiable) but
// still completes, so discovery proceeds with the announced full capability list.
HWTEST_F(HostSyncDeviceStatusRequestTest, MissingPeerBindingInvalidatesCredentialButAllowsDiscovery, TestSize.Level0)
{
    bool succeeded = false;
    std::vector<Capability> receivedCapabilities;
    auto request =
        MakeDefaultRequest([&succeeded, &receivedCapabilities](ResultCode result, const SyncDeviceStatus &status) {
            succeeded = result == SUCCESS;
            receivedCapabilities = status.companionCapabilityList;
        });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "bound peer returned no proof")).Times(1);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionCapabilityList.push_back(Capability::DELEGATE_AUTH);
    message.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(receivedCapabilities, (std::vector<Capability> { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH }));
}

// A failed proof verification invalidates the binding regardless of which user the reply
// announced; the sync round itself still succeeds and learns the announced key for routing.
HWTEST_F(HostSyncDeviceStatusRequestTest, FailedProofInvalidatesAndRoundStillSucceeds, TestSize.Level0)
{
    constexpr int32_t NEXT_USER_ID = 201;
    ResultCode received = GENERAL_ERROR;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(GENERAL_ERROR));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync companion check failed")).Times(1);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey.deviceUserId = NEXT_USER_ID;
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, NEXT_USER_ID);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 100);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_SYNC_DEVICE_STATUS_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);

    EXPECT_FALSE(result);
}

// The sync round must not bring its own peer online, or the request would end up waiting on the
// very round it is about to start.
HWTEST_F(HostSyncDeviceStatusRequestTest, RequireSyncedDevice_IsFalse, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    EXPECT_FALSE(request->RequireSyncedDevice());
}

// An announced list that is empty or has no overlap with the local offer stops the round with
// the specific negotiation code instead of falling through to the security layer.
HWTEST_F(HostSyncDeviceStatusRequestTest, ValidateReplyParameters_RejectsEmptyIntersection, TestSize.Level0)
{
    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto reply = MakeDefaultSyncDeviceStatusReply();
    reply.companionProofProtocolIdList.clear();
    EXPECT_EQ(request->ValidateReplyParameters(reply), PROTOCOL_NEGOTIATION_FAILED);
    reply.companionProofProtocolIdList = { ProtocolId::VERSION_2 };
    EXPECT_EQ(request->ValidateReplyParameters(reply), PROTOCOL_NEGOTIATION_FAILED);
    reply.companionProofProtocolIdList = { ProtocolId::VERSION_1 };
    EXPECT_EQ(request->ValidateReplyParameters(reply), SUCCESS);
}

// A divergence found after the proof verified is authenticated and invalidates the binding
// regardless of which user key the discovery cache holds; the round itself still succeeds.
HWTEST_F(HostSyncDeviceStatusRequestTest, DivergedListWithUntrustedUserKeyStillInvalidates, TestSize.Level0)
{
    constexpr int32_t CLAIMED_USER_ID = 201;
    ResultCode received = SUCCESS;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(PROTOCOL_NEGOTIATION_FAILED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, "sync protocol list diverged")).Times(1);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionDeviceKey.deviceUserId = CLAIMED_USER_ID;
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
    EXPECT_EQ(request->companionDeviceKey_.deviceUserId, CLAIMED_USER_ID);
}

// A secure protocol the Rust layer cannot consume is rejected (20013) and invalidates the
// binding; the sync round itself still succeeds.
HWTEST_F(HostSyncDeviceStatusRequestTest, FutureSecureProtocolInvalidatesTemplate, TestSize.Level0)
{
    ResultCode received = GENERAL_ERROR;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(SECURE_PROTOCOL_NOT_SUPPORTED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync companion check failed")).Times(1);
    Attributes reply;
    EncodeSyncDeviceStatusReply(MakeDefaultSyncDeviceStatusReply(), reply);
    reply.SetUint16Value(Attributes::ATTR_CDA_SA_SECURE_PROTOCOL_ID, 2); // future version
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
}

// An authenticated enrolled-protocol divergence invalidates with the divergence-specific reason;
// the sync round itself still succeeds.
HWTEST_F(HostSyncDeviceStatusRequestTest, DivergedEnrolledProtocolInvalidatesWithReason, TestSize.Level0)
{
    ResultCode received = GENERAL_ERROR;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(PROTOCOL_NEGOTIATION_FAILED));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync protocol list diverged")).Times(1);
    Attributes reply;
    EncodeSyncDeviceStatusReply(MakeDefaultSyncDeviceStatusReply(), reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, SUCCESS);
}

// V2 companion binding: the outbound SYNC is protected — the resolved-identity challenge round
// trip and HostBindingSign attach the binding signature attributes to the outgoing message; a
// GENERAL_ERROR resolve (legacy peer on an unknown message) downgrades to an unprotected V1
// offer without ever reaching HostBindingSign or touching the credentials.
HWTEST_F(HostSyncDeviceStatusRequestTest, SendSyncDeviceStatusRequest_002, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    const std::vector<uint8_t> signature(64, 0xEE);
    bool challengeResolveSucceeds = true;
    std::vector<uint8_t> sentChallenge;
    std::vector<uint8_t> sentSignature;
    int32_t sentCompanionUserId = 0;
    AttachV2BindingSignatureMocks(challenge, signature, challengeResolveSucceeds, sentChallenge, sentSignature,
        sentCompanionUserId);

    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = MakeDefaultRequest(std::move(callback));

    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(challenge, sentChallenge);
    EXPECT_EQ(signature, sentSignature);
    EXPECT_EQ(COMPANION_DEVICE_KEY.deviceUserId, sentCompanionUserId);

    // dispatched internal-error reply downgrades: the SYNC goes out unprotected with {VERSION_1},
    // HostBindingSign never runs, no credential is invalidated at challenge time
    challengeResolveSucceeds = false;
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);

    OnMessageReply downgradeCallback;
    ExpectChallengeFailureDowngrade(downgradeCallback);

    auto errorCalled = std::make_shared<bool>(false);
    auto errorCallback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto failing = MakeDefaultRequest(std::move(errorCallback));
    failing->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    DeliverSyncReply(downgradeCallback, MakeDefaultSyncDeviceStatusReply());
    EXPECT_FALSE(*errorCalled);
}

// The downgrade round's own reply is judged by the same empty-proof rule: a GENERAL_ERROR
// challenge followed by a proofless SUCCESS reply invalidates the credential while the round
// itself still completes (rule 5 combined with ruling 4 — the phantom-scenario cost).
HWTEST_F(HostSyncDeviceStatusRequestTest, DowngradedRoundEmptyProofInvalidatesButRoundSucceeds, TestSize.Level0)
{
    CompanionStatus v2Bound = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Bound });
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    OnMessageReply messageCallback;
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillOnce(Invoke([&](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
            EXPECT_EQ(MessageType::GET_BINDING_SIGNATURE_CHALLENGE, msgType);
            GetBindingSignatureChallengeReply challengeReply = {};
            challengeReply.result = ResultCode::GENERAL_ERROR;
            Attributes replyAttributes;
            EncodeGetBindingSignatureChallengeReply(challengeReply, replyAttributes);
            onReply(replyAttributes);
            return true;
        }))
        .WillOnce(Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply reply) {
            EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
            std::vector<uint16_t> protocols;
            EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
            EXPECT_EQ(protocols, std::vector<uint16_t> { static_cast<uint16_t>(ProtocolId::VERSION_1) });
            EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE));
            EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE));
            messageCallback = std::move(reply);
            return true;
        }));
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(v2Bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(v2Bound.templateId, "bound peer returned no proof")).Times(1);

    bool succeeded = false;
    auto request = MakeDefaultRequest(
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_TRUE(messageCallback);
    auto replyData = MakeDefaultSyncDeviceStatusReply();
    replyData.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(replyData, reply);
    SetCompanionSrcIdentifier(reply);
    messageCallback(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
}

// NOT_ENROLLED from the challenge round is a definitive state answer (ruling 2026-11-19), not a
// transport failure — but the reply names no user, and only the peer's current user may be
// invalidated. The round is redone as an unsigned discovery sync whose reply names the current
// user: that one credential is invalidated by the empty-proof rule, while another peer user's
// credential that has not come online survives untouched.
HWTEST_F(HostSyncDeviceStatusRequestTest, NotEnrolledChallengeReplyInvalidatesV2Candidate, TestSize.Level0)
{
    CompanionStatus v2Candidate = MakeV2CompanionStatus();
    CompanionStatus offlineUser = MakeV2CompanionStatus();
    offlineUser.templateId = 2;
    offlineUser.companionDeviceStatus.deviceKey.deviceUserId = 201;
    MakeStatusesVisible({ v2Candidate, offlineUser });
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(Invoke([](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
            if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                GetBindingSignatureChallengeReply challengeReply = {};
                challengeReply.result = ResultCode::NOT_ENROLLED;
                Attributes replyAttributes;
                EncodeGetBindingSignatureChallengeReply(challengeReply, replyAttributes);
                onReply(replyAttributes);
                return true;
            }
            EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
            SyncDeviceStatusReply replyData = MakeDefaultSyncDeviceStatusReply();
            replyData.companionCheckResponse.clear();
            onReply(MakeReplyAttributes(replyData));
            return true;
        }));

    bool succeeded = false;
    auto request = MakeDefaultRequest(
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);
    // the redo reply names the current user (200): only that credential is invalidated, by the
    // empty-proof rule; the offline user's row is never swept by the challenge answer
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(v2Candidate)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(v2Candidate.templateId, "bound peer returned no proof"))
        .Times(1);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(Ne(v2Candidate.templateId), _)).Times(0);

    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
}

// A TYPE_NOT_SUPPORT resolve (old peer SA has no handler; the router's raw error reply passes
// through the requester mapping) downgrades this round to unprotected V1 sync: the SYNC keeps the
// trimmed {VERSION_1} offer without signature attributes and the V2 candidate survives.
HWTEST_F(HostSyncDeviceStatusRequestTest, UnsupportedChallengeMessageDowngradesToV1Sync, TestSize.Level0)
{
    CompanionStatus v2Candidate = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Candidate });

    OnMessageReply messageCallback;
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(
            Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply &&onReply) {
                if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                    GetBindingSignatureChallengeReply challengeReply = {};
                    challengeReply.result = ResultCode::TYPE_NOT_SUPPORT;
                    Attributes replyAttributes;
                    EncodeGetBindingSignatureChallengeReply(challengeReply, replyAttributes);
                    onReply(replyAttributes);
                    return true;
                }
                EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
                std::vector<uint16_t> protocols;
                EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
                EXPECT_EQ(protocols,
                    ProtocolIdConverter::ToUnderlyingVec(std::vector<ProtocolId> { ProtocolId::VERSION_1 }));
                EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE));
                EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE));
                messageCallback = std::move(onReply);
                return true;
            }));

    ResultCode received = SUCCESS;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);

    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(messageCallback != nullptr);
    EXPECT_EQ(received, SUCCESS);
}

// A dispatched LOCKED reply is retryable: the round fails without invalidating the candidate.
HWTEST_F(HostSyncDeviceStatusRequestTest, LockedChallengeReplyDoesNotInvalidateV2Candidate, TestSize.Level0)
{
    CompanionStatus v2Candidate = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Candidate });
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(Invoke([](const std::string &, MessageType, Attributes &, OnMessageReply &&onReply) {
            GetBindingSignatureChallengeReply challengeReply = {};
            challengeReply.result = ResultCode::LOCKED;
            Attributes replyAttributes;
            EncodeGetBindingSignatureChallengeReply(challengeReply, replyAttributes);
            onReply(replyAttributes);
            return true;
        }));

    ResultCode received = SUCCESS;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);

    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, LOCKED);
}

// A matched V2 binding answered with SUCCESS and an empty proof means the round is unverifiable:
// the template is invalidated, the sync round itself still succeeds.
HWTEST_F(HostSyncDeviceStatusRequestTest, V2BoundPeerEmptyProofInvalidates, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    const std::vector<uint8_t> signature(64, 0xEE);
    CompanionStatus v2Bound = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Bound });
    ON_CALL(mockSecurityAgent_, HostBindingSign(_, _))
        .WillByDefault(Invoke([&signature](const HostBindingSignInput &, HostBindingSignOutput &output) {
            output.signature = signature;
            return ResultCode::SUCCESS;
        }));

    OnMessageReply messageCallback;
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(Invoke([&](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
            if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                    UserKey { COMPANION_DEVICE_KEY.deviceUserId, COMPANION_DEVICE_KEY.deviceSubProfileId }, challenge);
                return true;
            }
            EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
            messageCallback = std::move(onReply);
            return true;
        }));

    bool succeeded = false;
    auto request = MakeDefaultRequest(
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillRepeatedly(Return(std::make_optional(v2Bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(v2Bound.templateId, "bound peer returned no proof")).Times(1);

    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_TRUE(messageCallback);
    auto replyData = MakeDefaultSyncDeviceStatusReply();
    replyData.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(replyData, reply);
    SetCompanionSrcIdentifier(reply);
    messageCallback(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
}

// A matched V2 identity overrides the trimmed base offer: the dispatched SYNC carries the full
// host protocol list and the reply validates against that full list.
HWTEST_F(HostSyncDeviceStatusRequestTest, MatchedV2IdentityRestoresFullOffer, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    const std::vector<uint8_t> signature(64, 0xEE);
    CompanionStatus v2Bound = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Bound });
    ON_CALL(mockSecurityAgent_, HostBindingSign(_, _))
        .WillByDefault(Invoke([&signature](const HostBindingSignInput &, HostBindingSignOutput &output) {
            output.signature = signature;
            return ResultCode::SUCCESS;
        }));
    auto profile = MakeDualProtocolProfile();
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    OnMessageReply messageCallback;
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(
            Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply &&onReply) {
                if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                    ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                        UserKey { COMPANION_DEVICE_KEY.deviceUserId, COMPANION_DEVICE_KEY.deviceSubProfileId },
                        challenge);
                    return true;
                }
                EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
                std::vector<uint16_t> protocols;
                EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
                EXPECT_EQ(protocols, ProtocolIdConverter::ToUnderlyingVec(profile.hostProtocols));
                messageCallback = std::move(onReply);
                return true;
            }));

    bool succeeded = false;
    auto request = MakeDefaultRequest(
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillRepeatedly(Return(std::make_optional(v2Bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Invoke([](const HostEndCompanionCheckInput &, HostEndCompanionCheckOutput &output) {
            output.companionCapabilityList =
                CapabilityConverter::ToUnderlyingVec(MakeDefaultSyncDeviceStatusReply().companionCapabilityList);
            return SUCCESS;
        }));

    request->OnConnected();
    TaskRunnerManager::GetInstance().ExecuteAll();
    auto replyData = MakeDefaultSyncDeviceStatusReply();
    replyData.companionProofProtocolIdList = { ProtocolId::VERSION_2 };
    replyData.companionSupportedProtocolIdList = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    DeliverSyncReply(messageCallback, replyData);
    EXPECT_TRUE(succeeded);
}

// An unmatched challenge identity with no local credential restores the full offer: the round is
// discovery for the resolved identity and is not trimmed for another user's binding.
HWTEST_F(HostSyncDeviceStatusRequestTest, UnmatchedChallengeIdentityRestoresFullOffer, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    CompanionStatus v2Candidate = MakeV2CompanionStatus();
    MakeStatusesVisible({ v2Candidate });
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    OnMessageReply messageCallback;
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(
            Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply &&onReply) {
                if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                    ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                        UserKey { 999, INVALID_SUB_PROFILE_ID }, challenge);
                    return true;
                }
                EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
                std::vector<uint16_t> protocols;
                EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
                EXPECT_EQ(protocols, ProtocolIdConverter::ToUnderlyingVec(profile.hostProtocols));
                messageCallback = std::move(onReply);
                return true;
            }));

    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);

    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(messageCallback != nullptr);
}

// An unmatched identity that still maps to a local V1 credential keeps the trimmed {VERSION_1}
// offer: the peer proves that binding and a legacy whole-list validation must not see V2.
HWTEST_F(HostSyncDeviceStatusRequestTest, UnmatchedChallengeIdentityWithV1BindingKeepsTrimmedOffer, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    CompanionStatus v2Candidate = MakeV2CompanionStatus();
    CompanionStatus v1Bound = {};
    v1Bound.templateId = 2;
    v1Bound.hostUserKey = UserKey { HOST_USER_ID, INVALID_SUB_PROFILE_ID };
    v1Bound.isValid = true;
    v1Bound.enrolledProtocolId = ProtocolId::VERSION_1;
    v1Bound.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    v1Bound.companionDeviceStatus.deviceKey.deviceUserId = 999;
    v1Bound.companionDeviceStatus.deviceKey.deviceSubProfileId = INVALID_SUB_PROFILE_ID;
    MakeStatusesVisible({ v2Candidate, v1Bound });
    // the keyed identity lookup must hit the V1 row for the challenge-resolved user
    ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
        .WillByDefault(Invoke([v1Bound](const UserKey &hostUserKey, const DeviceKey &deviceKey) {
            return (v1Bound.hostUserKey == hostUserKey && v1Bound.companionDeviceStatus.deviceKey == deviceKey)
                ? std::make_optional(v1Bound)
                : std::nullopt;
        }));
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    OnMessageReply messageCallback;
    ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillByDefault(
            Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply &&onReply) {
                if (msgType == MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                    ReplyBindingSignatureChallenge(onReply, ResultCode::SUCCESS,
                        UserKey { 999, INVALID_SUB_PROFILE_ID }, challenge);
                    return true;
                }
                EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
                std::vector<uint16_t> protocols;
                EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
                EXPECT_EQ(protocols,
                    ProtocolIdConverter::ToUnderlyingVec(std::vector<ProtocolId> { ProtocolId::VERSION_1 }));
                messageCallback = std::move(onReply);
                return true;
            }));

    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);

    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(messageCallback != nullptr);
}

// Invalid credentials stay invalid: an invalid-only device holds no valid binding, so the
// challenge gate stays shut and the round goes out as an unprotected full-offer discovery.
HWTEST_F(HostSyncDeviceStatusRequestTest, InvalidOnlyBindingSendsDiscoveryRound, TestSize.Level0)
{
    CompanionStatus invalidated = MakeBoundCompanionStatus();
    invalidated.isValid = false;
    MakeStatusesVisible({ invalidated });
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    OnMessageReply messageCallback;
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillOnce(Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply reply) {
            EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
            std::vector<uint16_t> protocols;
            EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
            EXPECT_EQ(protocols, ProtocolIdConverter::ToUnderlyingVec(profile.hostProtocols));
            EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE));
            EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE));
            messageCallback = std::move(reply);
            return true;
        }));
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    // the invalid credential resolves for the reply, but it must never be re-reported
    // (no repeated system fault) and its flag must not flip
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(invalidated)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    // only the valid-binding gate enumerates; the invalid credential drops out and no further scan follows
    EXPECT_CALL(mockCompanionManager_, FilterCompanionStatus(_, _, _)).Times(1);

    bool succeeded = false;
    auto request = MakeDefaultRequest(
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_TRUE(messageCallback);
    auto replyData = MakeDefaultSyncDeviceStatusReply();
    replyData.companionCheckResponse.clear();
    Attributes reply;
    EncodeSyncDeviceStatusReply(replyData, reply);
    SetCompanionSrcIdentifier(reply);
    messageCallback(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
}

// Rule 10: two host users bound to the same watch user at different versions. Host user Y's
// sync must not be hijacked by host user X's V2 candidate: the host-scoped scan only sees Y's
// own V1 credential, so the round goes out unprotected in one message with the offer trimmed
// to {VERSION_1} — no challenge roundtrip, no signing.
HWTEST_F(HostSyncDeviceStatusRequestTest, MultiHostUserSyncNotHijackedByOtherHostsV2Candidate, TestSize.Level0)
{
    constexpr int32_t OTHER_HOST_USER_ID = 101;
    UserKey yHostUser { OTHER_HOST_USER_ID, INVALID_SUB_PROFILE_ID };
    CompanionStatus xBinding = MakeV2CompanionStatus();
    CompanionStatus yBinding = {};
    yBinding.templateId = 2;
    yBinding.hostUserKey = yHostUser;
    yBinding.isValid = true;
    yBinding.enrolledProtocolId = ProtocolId::VERSION_1;
    yBinding.companionDeviceStatus.deviceKey = COMPANION_DEVICE_KEY;
    MakeStatusesVisible({ xBinding, yBinding });
    auto profile = MakeDualProtocolProfile();
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    OnMessageReply messageCallback;
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillOnce(Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply reply) {
            EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
            std::vector<uint16_t> protocols;
            EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
            EXPECT_EQ(protocols, std::vector<uint16_t> { static_cast<uint16_t>(ProtocolId::VERSION_1) });
            EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE));
            EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE));
            messageCallback = std::move(reply);
            return true;
        }));
    EXPECT_CALL(mockSecurityAgent_, HostBindingSign(_, _)).Times(0);
    // host-scoped valid gate and V1-only shortcut; X's V2 candidate is invisible to Y's scans
    EXPECT_CALL(mockCompanionManager_, FilterCompanionStatus(_, _, _)).Times(2);
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(yHostUser, _))
        .WillRepeatedly(Return(std::make_optional(yBinding)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Invoke([](const HostEndCompanionCheckInput &input, HostEndCompanionCheckOutput &output) {
            EXPECT_EQ(input.templateId, 2);
            output.companionCapabilityList =
                CapabilityConverter::ToUnderlyingVec(MakeDefaultSyncDeviceStatusReply().companionCapabilityList);
            return SUCCESS;
        }));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);

    bool succeeded = false;
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(yHostUser, COMPANION_DEVICE_KEY, CONNECTION_MODE,
        SyncTriggerReason::EXTERNAL_REFRESH,
        [&succeeded](ResultCode result, const SyncDeviceStatus &) { succeeded = result == SUCCESS; });
    ASSERT_NE(request, nullptr);
    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    DeliverSyncReply(messageCallback, MakeDefaultSyncDeviceStatusReply());
    EXPECT_TRUE(succeeded);
}

// Card 9: the host holds no credential while the watch answers a discovery round over a
// lingering V1 binding; the cache takes the announced full capability list (never empty) and
// the negotiated value follows the actually-sent offer.
HWTEST_F(HostSyncDeviceStatusRequestTest, DiscoveryRoundCachesFullAnnouncedCapabilities, TestSize.Level0)
{
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    profile.hostCapabilities.push_back(Capability::DELEGATE_AUTH);
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    OnMessageReply messageCallback;
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _))
        .WillOnce(Invoke([&](const std::string &, MessageType msgType, Attributes &request, OnMessageReply reply) {
            EXPECT_EQ(MessageType::SYNC_DEVICE_STATUS, msgType);
            std::vector<uint16_t> protocols;
            EXPECT_TRUE(request.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocols));
            EXPECT_EQ(protocols, ProtocolIdConverter::ToUnderlyingVec(profile.hostProtocols));
            messageCallback = std::move(reply);
            return true;
        }));
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);

    bool succeeded = false;
    std::vector<Capability> receivedCapabilities;
    uint16_t selectedProtocolId = 0;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        succeeded = result == SUCCESS;
        receivedCapabilities = status.companionCapabilityList;
        selectedProtocolId = status.selectedProtocolId;
    });
    ASSERT_NE(request, nullptr);
    request->BeginCompanionCheck();
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_TRUE(messageCallback);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionProofProtocolIdList = { ProtocolId::VERSION_1 };
    message.companionCapabilityList = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    messageCallback(reply);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(succeeded);
    EXPECT_EQ(receivedCapabilities, (std::vector<Capability> { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH }));
    EXPECT_EQ(selectedProtocolId, static_cast<uint16_t>(ProtocolId::VERSION_1));
}

// A failed verification invalidates the credential, so the round concludes as a discovery round:
// version and capabilities are published from the same discovery state, never a half-mix of an
// authenticated version with an empty capability set.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_CheckFailureConcludesAsDiscovery, TestSize.Level0)
{
    auto successCalled = std::make_shared<bool>(false);
    std::vector<Capability> receivedCapabilities;
    auto callback = [&successCalled, &receivedCapabilities](ResultCode result, const SyncDeviceStatus &status) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
            receivedCapabilities = status.companionCapabilityList;
        }
    };
    auto request = MakeDefaultRequest(std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    Attributes reply = MakeReplyAttributes(syncDeviceStatusReply);

    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "sync companion check failed")).Times(1);

    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
    EXPECT_EQ(receivedCapabilities, syncDeviceStatusReply.companionCapabilityList);
}

// A credential invalidated mid-round must not publish a binding view, and no make-up message is
// added: the round concludes from this very reply, with freshBinding computed over the FULL host
// profile against the peer's complete support set — complete even though the round's offer was
// narrowed to {V1} by the now-dead credential.
HWTEST_F(HostSyncDeviceStatusRequestTest, InvalidatedRoundPublishesFreshBindingFromFullSupportSet, TestSize.Level0)
{
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).Times(0);

    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(bound.templateId, "bound peer returned no proof")).Times(1);

    bool succeeded = false;
    std::vector<Capability> receivedCapabilities;
    uint16_t selectedProtocolId = 0;
    uint16_t freshBindingProtocolId = 0;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        succeeded = result == SUCCESS;
        receivedCapabilities = status.companionCapabilityList;
        selectedProtocolId = status.selectedProtocolId;
        freshBindingProtocolId = status.freshBindingProtocolId;
    });
    ASSERT_NE(request, nullptr);
    // the failed round ran under a credential-restricted offer
    request->sentProtocolIdList_ = { ProtocolId::VERSION_1 };

    auto replyData = MakeDefaultSyncDeviceStatusReply();
    replyData.companionCheckResponse.clear();
    replyData.companionCapabilityList = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    replyData.companionProofProtocolIdList = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    replyData.companionSupportedProtocolIdList = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    Attributes reply;
    EncodeSyncDeviceStatusReply(replyData, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(succeeded);
    EXPECT_EQ(selectedProtocolId, static_cast<uint16_t>(ProtocolId::VERSION_2));
    EXPECT_EQ(freshBindingProtocolId, static_cast<uint16_t>(ProtocolId::VERSION_2));
    EXPECT_EQ(receivedCapabilities, (std::vector<Capability> { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH }));
}

// A re-validated binding pins selected at its enrolled version while freshBinding still reflects
// the peer's complete support set: both values coexist in one snapshot (scenario: valid V1 binding,
// both sides support V2). The peer proves with VERSION_1 alone and announces the complete set on
// its own field; the published list is the complete set.
HWTEST_F(HostSyncDeviceStatusRequestTest, AuthenticatedRoundKeepsEnrolledWhileFreshBindingTracksFullSet,
    TestSize.Level0)
{
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    auto bound = MakeBoundCompanionStatus();
    bound.enrolledProtocolId = ProtocolId::VERSION_1;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillOnce(Invoke([](const HostEndCompanionCheckInput &, HostEndCompanionCheckOutput &output) {
            output.companionCapabilityList = { static_cast<uint16_t>(Capability::TOKEN_AUTH) };
            return SUCCESS;
        }));

    bool succeeded = false;
    std::vector<Capability> receivedCapabilities;
    uint16_t selectedProtocolId = 0;
    uint16_t freshBindingProtocolId = 0;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        succeeded = result == SUCCESS;
        receivedCapabilities = status.companionCapabilityList;
        selectedProtocolId = status.selectedProtocolId;
        freshBindingProtocolId = status.freshBindingProtocolId;
    });
    ASSERT_NE(request, nullptr);
    // V1-credential round: the offer was narrowed to {V1} before dispatch
    request->sentProtocolIdList_ = { ProtocolId::VERSION_1 };

    auto replyData = MakeDefaultSyncDeviceStatusReply();
    replyData.companionCapabilityList = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };
    replyData.companionProofProtocolIdList = { ProtocolId::VERSION_1 };
    replyData.companionSupportedProtocolIdList = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    Attributes reply;
    EncodeSyncDeviceStatusReply(replyData, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(succeeded);
    EXPECT_EQ(selectedProtocolId, static_cast<uint16_t>(ProtocolId::VERSION_1));
    EXPECT_EQ(freshBindingProtocolId, static_cast<uint16_t>(ProtocolId::VERSION_2));
    // the published protocol view is the peer's complete support set, reported via the event
    EXPECT_NE(request->eventCollector_.GetExtraInfo().find("peerProtocolIdList:[2, 1]"), std::string::npos);
    // the authenticated capability set wins over the announcement for the binding view
    EXPECT_EQ(receivedCapabilities, std::vector<Capability> { Capability::TOKEN_AUTH });
}

// A peer that does not send the dedicated field (a peer predating it) announces its complete set in
// the proof list field: decode defaults the support set to it, so freshBinding and the published
// list both come from that list.
HWTEST_F(HostSyncDeviceStatusRequestTest, FreshBindingFallsBackToProofListWithoutDedicatedSupportSet, TestSize.Level0)
{
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillRepeatedly(Return(std::make_optional(bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillRepeatedly(Invoke([](const HostEndCompanionCheckInput &, HostEndCompanionCheckOutput &output) {
            output.companionCapabilityList = { static_cast<uint16_t>(Capability::TOKEN_AUTH) };
            return SUCCESS;
        }));

    struct Scenario {
        std::vector<ProtocolId> announced;
        ProtocolId expectedFresh;
        std::string expectedReported;
    };
    const std::vector<Scenario> scenarios = { { { ProtocolId::VERSION_1 }, ProtocolId::VERSION_1,
                                                  "peerProtocolIdList:[1]" },
        { { ProtocolId::VERSION_2, ProtocolId::VERSION_1 }, ProtocolId::VERSION_2, "peerProtocolIdList:[2, 1]" } };

    for (const auto &scenario : scenarios) {
        bool succeeded = false;
        uint16_t selectedProtocolId = 0;
        uint16_t freshBindingProtocolId = 0;
        auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
            succeeded = result == SUCCESS;
            selectedProtocolId = status.selectedProtocolId;
            freshBindingProtocolId = status.freshBindingProtocolId;
        });
        ASSERT_NE(request, nullptr);
        request->sentProtocolIdList_ = { ProtocolId::VERSION_1 };

        auto replyData = MakeDefaultSyncDeviceStatusReply();
        replyData.companionProofProtocolIdList = scenario.announced;
        Attributes reply = EncodeOldPeerSyncDeviceStatusReply(replyData);
        request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
        TaskRunnerManager::GetInstance().ExecuteAll();

        EXPECT_TRUE(succeeded);
        EXPECT_EQ(selectedProtocolId, static_cast<uint16_t>(ProtocolId::VERSION_1));
        EXPECT_EQ(freshBindingProtocolId, static_cast<uint16_t>(scenario.expectedFresh));
        EXPECT_NE(request->eventCollector_.GetExtraInfo().find(scenario.expectedReported), std::string::npos);
    }
}

// The support set is checked for structure only: it must cover the proof list. A failure fails the
// round and leaves the credential alone. Decode defaults the field to the proof list for peers
// predating the attribute, so a defaulted value passes trivially; the non-covering shape here is
// exactly the carried-but-inconsistent one.
HWTEST_F(HostSyncDeviceStatusRequestTest, ValidateReplyParameters_ChecksCarriedSupportSet, TestSize.Level0)
{
    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    // A defaulted support set equals the (already checked non-empty) proof list and passes.
    auto reply = MakeDefaultSyncDeviceStatusReply();
    reply.companionSupportedProtocolIdList = reply.companionProofProtocolIdList;
    EXPECT_EQ(request->ValidateReplyParameters(reply), SUCCESS);

    // The proof list is {VERSION_1}: a support set without it is inconsistent.
    reply.companionSupportedProtocolIdList = std::vector<ProtocolId> { ProtocolId::VERSION_2 };
    EXPECT_EQ(request->ValidateReplyParameters(reply), PROTOCOL_NEGOTIATION_FAILED);

    reply.companionSupportedProtocolIdList = std::vector<ProtocolId> { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    EXPECT_EQ(request->ValidateReplyParameters(reply), SUCCESS);
}

// A protocol value a later version may list and this host does not know.
constexpr ProtocolId FUTURE_PROTOCOL_ID = static_cast<ProtocolId>(999);

// A peer of a higher version may list protocols this host does not know. They are only ever looked
// past: the round is judged by the values the two peers have in common.
HWTEST_F(HostSyncDeviceStatusRequestTest, ValidateReplyParameters_ToleratesUnknownProtocolOfHigherVersionPeer,
    TestSize.Level0)
{
    auto request = MakeDefaultRequest([](ResultCode, const SyncDeviceStatus &) {});
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;

    // The proof list narrows to what the host offered; the complete set reaches beyond it.
    auto reply = MakeDefaultSyncDeviceStatusReply();
    reply.companionProofProtocolIdList = { ProtocolId::VERSION_1 };
    reply.companionSupportedProtocolIdList = { ProtocolId::VERSION_1, ProtocolId::VERSION_2, FUTURE_PROTOCOL_ID };
    EXPECT_EQ(request->ValidateReplyParameters(reply), SUCCESS);

    // An unknown value inside the proof list is judged the same way, by its place in the peer's set.
    reply.companionProofProtocolIdList = { ProtocolId::VERSION_1, FUTURE_PROTOCOL_ID };
    EXPECT_EQ(request->ValidateReplyParameters(reply), SUCCESS);
}

// With a higher-version peer the fresh binding protocol stays the best value both sides know; the
// value only the peer knows rides along in the protocol list and picks nothing.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_HigherVersionPeer_FreshBindingIsBestCommon,
    TestSize.Level0)
{
    LocalDeviceProfile profile = PROFILE;
    profile.hostProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    auto bound = MakeBoundCompanionStatus();
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillRepeatedly(Return(std::make_optional(bound)));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _))
        .WillRepeatedly(Invoke([](const HostEndCompanionCheckInput &, HostEndCompanionCheckOutput &output) {
            output.companionCapabilityList = { static_cast<uint16_t>(Capability::TOKEN_AUTH) };
            return SUCCESS;
        }));

    bool succeeded = false;
    uint16_t freshBindingProtocolId = 0;
    auto request = MakeDefaultRequest([&](ResultCode result, const SyncDeviceStatus &status) {
        succeeded = result == SUCCESS;
        freshBindingProtocolId = status.freshBindingProtocolId;
    });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = { ProtocolId::VERSION_1 };

    auto replyData = MakeDefaultSyncDeviceStatusReply();
    replyData.companionProofProtocolIdList = { ProtocolId::VERSION_1 };
    replyData.companionSupportedProtocolIdList = { FUTURE_PROTOCOL_ID, ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    Attributes reply;
    EncodeSyncDeviceStatusReply(replyData, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(succeeded);
    EXPECT_EQ(freshBindingProtocolId, static_cast<uint16_t>(ProtocolId::VERSION_2));
    // the value only the peer knows rides along in the reported support set and picks nothing
    EXPECT_NE(request->eventCollector_.GetExtraInfo().find("peerProtocolIdList:[999, 2, 1]"), std::string::npos);
}

// An inconsistent carried support set fails the structural pre-filter before the security layer
// runs; the rejection fails the round but does not invalidate the binding.
HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_RejectsSupportSetNotCoveringProofList,
    TestSize.Level0)
{
    ResultCode received = SUCCESS;
    auto request = MakeDefaultRequest([&received](ResultCode result, const SyncDeviceStatus &) { received = result; });
    ASSERT_NE(request, nullptr);
    request->sentProtocolIdList_ = PROFILE.hostProtocols;
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_, _)).Times(0);
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).Times(0);
    auto message = MakeDefaultSyncDeviceStatusReply();
    message.companionSupportedProtocolIdList = std::vector<ProtocolId> { ProtocolId::VERSION_2 };
    Attributes reply;
    EncodeSyncDeviceStatusReply(message, reply);
    SetCompanionSrcIdentifier(reply);
    request->HandleSyncDeviceStatusReply(reply, std::make_shared<Attributes>());
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(received, PROTOCOL_NEGOTIATION_FAILED);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
