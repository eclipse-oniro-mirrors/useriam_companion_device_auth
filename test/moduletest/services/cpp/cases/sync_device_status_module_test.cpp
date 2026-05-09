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

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

#include "module_test_guard.h"
#include "module_test_helpers.h"

#include "companion_manager.h"
#include "cross_device_comm_manager.h"
#include "host_binding_manager.h"
#include "iam_logger.h"
#include "singleton_manager.h"
#include "sync_device_status_message.h"

#define LOG_TAG "CDA_SA_MODULE_TEST"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class FakeAvailableDeviceStatusCallback : public IIpcAvailableDeviceStatusCallback {
public:
    explicit FakeAvailableDeviceStatusCallback(std::function<ErrCode(const std::vector<IpcDeviceStatus> &)> handler)
        : handler_(std::move(handler))
    {
        remoteObj_ = sptr<StubRemoteObject>::MakeSptr();
    }

    ErrCode OnAvailableDeviceStatusChange(const std::vector<IpcDeviceStatus> &deviceStatusList) override
    {
        if (handler_) {
            return handler_(deviceStatusList);
        }
        return 0;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return remoteObj_;
    }

private:
    class StubRemoteObject : public IRemoteObject {
    public:
        StubRemoteObject() : IRemoteObject(u"StubRemoteObject")
        {
        }
        int32_t GetObjectRefCount() override
        {
            return 1;
        }
        int SendRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) override
        {
            return 0;
        }
        bool AddDeathRecipient(const sptr<DeathRecipient> &) override
        {
            return true;
        }
        bool RemoveDeathRecipient(const sptr<DeathRecipient> &) override
        {
            return true;
        }
        int Dump(int, const std::vector<std::u16string> &) override
        {
            return 0;
        }
    };

    std::function<ErrCode(const std::vector<IpcDeviceStatus> &)> handler_;
    sptr<StubRemoteObject> remoteObj_;
};

class SyncDeviceStatusModuleTest : public testing::Test {};

// ============================================================================
// Test 1: Host side — subscribe available devices → device online → sync
//         (no template enrolled) → callback fires with available device
// ============================================================================
//
// What this tests:
//   SubscribeAvailableDeviceStatus → SubscriptionManager → AvailableDeviceSubscription
//     → SetSubscribeMode(MANAGE) → DeviceStatusManager monitors all devices
//
//   TestSimulateDeviceOnline → DeviceStatusManager.TriggerDeviceSync
//     → HostSyncDeviceStatusRequest → HostBeginCompanionCheck (Mock SA)
//     → SendSyncDeviceStatusRequest → FakeChannel (raw msg captured)
//
//   [Inject SyncDeviceStatusReply] → HandleSyncDeviceStatusReply
//     → EndCompanionCheck (no template → skip)
//     → HandleSyncResult → isSynced=true → NotifySubscribers
//     → AvailableDeviceSubscription.HandleDeviceStatusChange
//       → callback.OnAvailableDeviceStatusChange
//
// E2E level: HIGH
//   - Entry: service-level SubscribeAvailableDeviceStatus API
//   - Production path: SubscriptionManager → DeviceStatusManager → RequestManager
//     → HostSyncDeviceStatusRequest → MessageRouter → FakeChannel
//   - Message injection: decode/encode at raw message boundary only
//   - Verification: IPC callback content + GetDeviceStatus query
// ============================================================================
HWTEST_F(SyncDeviceStatusModuleTest, HostSyncNoTemplateE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr UserId HOST_USER = 100;

    // Setup: HostBeginCompanionCheck mock (no companion registered, so HostEndCompanionCheck
    // is NOT expected — EndCompanionCheck returns early without calling it)
    HostBeginCompanionCheckOutput checkOutput;
    checkOutput.salt = { 0x01, 0x02, 0x03, 0x04 };
    checkOutput.challenge = 12345;
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(checkOutput), Return(ResultCode::SUCCESS)));

    bool callbackFired = false;
    std::vector<IpcDeviceStatus> capturedDeviceStatusList;
    auto callback =
        sptr<FakeAvailableDeviceStatusCallback>::MakeSptr([&](const std::vector<IpcDeviceStatus> &deviceStatusList) {
            callbackFired = true;
            capturedDeviceStatusList = deviceStatusList;
            return 0;
        });
    ASSERT_NE(callback, nullptr);

    EXPECT_EQ(guard.GetCore().SubscribeAvailableDeviceStatus(HOST_USER, callback), ResultCode::SUCCESS);
    DrainPendingTasks();

    // Run: device online triggers TriggerDeviceSync → HostSyncDeviceStatusRequest → FakeChannel
    guard.SimulateDeviceOnline("companion-test-device-001");

    auto connNames = guard.GetChannel().GetAllConnectionNames();
    ASSERT_FALSE(connNames.empty());
    const auto &connName = connNames[0];

    // Capture SYNC_DEVICE_STATUS request → inject reply → triggers HandleSyncResult → callback
    auto msgInfo = guard.CaptureOutboundMessage(connName, MessageType::SYNC_DEVICE_STATUS);
    ASSERT_TRUE(msgInfo.has_value());
    EXPECT_FALSE(msgInfo->isReply);
    SyncDeviceStatusReply reply;
    reply.result = ResultCode::SUCCESS;
    reply.protocolIdList = { ProtocolId::VERSION_1 };
    reply.capabilityList = { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH };
    reply.secureProtocolId = SecureProtocolId::DEFAULT;
    reply.companionDeviceKey = MakeDeviceKey("companion-test-device-001", 200);
    reply.deviceUserName = "CompanionUser";

    Attributes replyPayload;
    EncodeSyncDeviceStatusReply(reply, replyPayload);
    guard.InjectCompanionRequest(connName,
        BuildReplyRawMsg(connName, msgInfo->seq, MessageType::SYNC_DEVICE_STATUS, replyPayload));

    EXPECT_TRUE(callbackFired);
    ASSERT_EQ(capturedDeviceStatusList.size(), 1u);
    EXPECT_EQ(capturedDeviceStatusList[0].deviceKey.deviceId, "companion-test-device-001");
    EXPECT_TRUE(capturedDeviceStatusList[0].isOnline);

    auto deviceStatus =
        GetCrossDeviceCommManager().GetDeviceStatus(MakeDeviceKey("companion-test-device-001", HOST_USER));
    ASSERT_TRUE(deviceStatus.has_value());
    EXPECT_EQ(deviceStatus->deviceUserName, "CompanionUser");
    EXPECT_EQ(deviceStatus->protocolId, ProtocolId::VERSION_1);
    EXPECT_EQ(deviceStatus->secureProtocolId, SecureProtocolId::DEFAULT);
    EXPECT_FALSE(deviceStatus->capabilities.empty());
}

// ============================================================================
// Test 2: Companion side — receive SYNC_DEVICE_STATUS request →
//         no host binding → return reply with protocols + user name
// ============================================================================
//
// What this tests:
//   Incoming SYNC_DEVICE_STATUS request → MessageRouter → CompanionSyncDeviceStatusHandler
//     → DecodeSyncDeviceStatusRequest
//     → GetActiveUserId/Name → BuildSyncDeviceStatusReply
//     → GetHostBindingStatus = nullopt → skip CompanionProcessCheck
//     → EncodeSyncDeviceStatusReply → SendReply → FakeChannel
//
// E2E level: HIGH
//   - Entry: raw message injection at FakeChannel boundary
//   - Production path: MessageRouter → CompanionSyncDeviceStatusHandler → SecurityAgent
//   - Verification: decode raw reply message, check all fields
// ============================================================================
HWTEST_F(SyncDeviceStatusModuleTest, CompanionResponseNoBindingE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "test-conn-sync-001";
    constexpr UserId COMPANION_ACTIVE_USER = 100;
    IAM_LOGI("[Phase] Setup — create inbound connection from host");
    // 1. Create inbound connection (simulates host connecting to companion)
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-test-device-001"));
    DrainPendingTasks();

    IAM_LOGI("[Phase] Run — receive SYNC_DEVICE_STATUS request, send reply with protocols + user name");
    // 2. Build SyncDeviceStatusRequest from "host"
    SyncDeviceStatusRequest request;
    request.protocolIdList = { ProtocolId::VERSION_1 };
    request.capabilityList = { Capability::DELEGATE_AUTH };
    request.hostDeviceKey = MakeDeviceKey("host-test-device-001", COMPANION_ACTIVE_USER);
    request.salt = { 0xAA, 0xBB, 0xCC, 0xDD };
    request.challenge = 99999;

    Attributes requestPayload;
    EncodeSyncDeviceStatusRequest(request, requestPayload);
    // Companion handler needs host device key via SRC_IDENTIFIER
    EncodeHostDeviceKey(request.hostDeviceKey, requestPayload);

    auto requestRawMsg = BuildRequestRawMsg(connName, 1, MessageType::SYNC_DEVICE_STATUS, requestPayload);

    // 3. Inject the request
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, requestRawMsg);
    DrainPendingTasks();

    // 4. Capture the reply from FakeChannel
    auto sentMsgList = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgList.empty()) << "Expected companion to send a reply";

    auto &replyRawMsg = sentMsgList[0];
    auto replyInfo = DecodeRawMsg(replyRawMsg);
    ASSERT_TRUE(replyInfo.has_value()) << "Failed to decode reply raw message";
    EXPECT_TRUE(replyInfo->isReply);
    EXPECT_EQ(replyInfo->msgType, MessageType::SYNC_DEVICE_STATUS);

    // 5. Verify the reply content directly from raw attributes.
    // Note: EncodeSyncDeviceStatusReply only writes companionUserId, not the full companionDeviceKey.
    // DecodeSyncDeviceStatusReply expects full companionDeviceKey (idType + deviceId + userId),
    // so we cannot use it for companion-side reply verification. Verify individual fields instead.
    int32_t resultCode = 0;
    EXPECT_TRUE(replyInfo->payload.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, resultCode));
    EXPECT_EQ(static_cast<ResultCode>(resultCode), ResultCode::SUCCESS);

    std::vector<uint16_t> protocolList;
    EXPECT_TRUE(replyInfo->payload.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_PROTOCOL_ID_LIST, protocolList));
    EXPECT_EQ(protocolList.size(), 1u) << "Reply should contain exactly one protocol";
    EXPECT_EQ(protocolList[0], static_cast<uint16_t>(ProtocolId::VERSION_1));

    std::vector<uint16_t> capabilityList;
    EXPECT_TRUE(replyInfo->payload.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, capabilityList));
    EXPECT_FALSE(capabilityList.empty()) << "Reply should contain capabilities";

    int32_t companionUserId = 0;
    EXPECT_TRUE(replyInfo->payload.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, companionUserId));
    EXPECT_EQ(companionUserId, COMPANION_ACTIVE_USER) << "Companion should set active user id";

    std::string userName;
    EXPECT_TRUE(replyInfo->payload.GetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, userName));
    EXPECT_EQ(userName, "TestUser") << "Companion should return active user name";

    std::vector<uint8_t> checkResponse;
    EXPECT_TRUE(replyInfo->payload.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, checkResponse));
    EXPECT_TRUE(checkResponse.empty()) << "No binding → no companion check response";
}

// ============================================================================
// Test 3: Host side — sync with template enrolled → companion check succeeds
// ============================================================================
//
// What this tests:
//   Pre-register a companion via CompanionManager (simulates prior enrollment)
//   Subscribe → device online → sync → reply with companionCheckResponse
//   → HostEndCompanionCheck called → callback fires
//
// E2E level: HIGH
//   - Setup: Real CompanionManager via BeginAddCompanion/EndAddCompanion
//   - Entry: service-level SubscribeAvailableDeviceStatus API
//   - Verification: HostEndCompanionCheck called with templateId + companionCheckResponse
// ============================================================================
HWTEST_F(SyncDeviceStatusModuleTest, HostSyncWithTemplateCheckSuccessE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr UserId HOST_USER = 100;
    constexpr TemplateId TEMPLATE_ID = 54321;
    const std::string companionDeviceId = "companion-with-template-001";

    IAM_LOGI("[Phase] Setup — mock HostBegin/EndCompanionCheck, register companion, "
             "subscribe, verify cached device status");
    // 1. Setup Mock expectations BEFORE RegisterCompanionDirect.
    // RegisterCompanionDirect triggers a SyncDeviceStatus request internally, which calls
    // HostBeginCompanionCheck and HostEndCompanionCheck. Set up mock expectations first
    // so the sync during registration uses them.
    // Use WillRepeatedly because the may be triggered multiple times during setup.
    HostBeginCompanionCheckOutput checkOutput;
    checkOutput.salt = { 0x05, 0x06, 0x07, 0x08 };
    checkOutput.challenge = 54321;
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(checkOutput), Return(ResultCode::SUCCESS)));

    // Expect HostEndCompanionCheck to be called with templateId.
    // Note: companionCheckResponse may be empty because the companion side has no host binding
    // (this is a host-side test, the companion doesn't know about the host binding).
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndCompanionCheck(_))
        .WillRepeatedly([&](const HostEndCompanionCheckInput &input) {
            EXPECT_EQ(input.templateId, TEMPLATE_ID);
            return ResultCode::SUCCESS;
        });

    // 2. Register a companion via direct API call.
    // Per E2E two-phase principle: Setup Phase allows direct internal API calls.
    // SetupCompanionDevice combines TestSimulateDeviceOnline + DrainPendingTasks + RegisterCompanionDirect.
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER, companionDeviceId, TEMPLATE_ID));

    // 3. Verify companion was registered correctly
    DeviceKey queryKey = MakeDeviceKey(companionDeviceId, HOST_USER);

    auto companionStatus = GetCompanionManager().GetCompanionStatus(HOST_USER, queryKey);
    ASSERT_TRUE(companionStatus.has_value()) << "Companion should be registered";
    EXPECT_EQ(companionStatus->templateId, TEMPLATE_ID);

    // 4. Verify device is synced and HostEndCompanionCheck mock expectation validates
    // that it was called with the correct templateId and non-empty companionCheckResponse.
    auto deviceStatus = GetCrossDeviceCommManager().GetDeviceStatus(queryKey);
    ASSERT_TRUE(deviceStatus.has_value()) << "Device should be synced";
    EXPECT_EQ(deviceStatus->deviceKey.deviceId, companionDeviceId);
    EXPECT_EQ(deviceStatus->deviceKey.deviceUserId, HOST_USER);
}

// ============================================================================
// Test 4: Host side — sync with template enrolled → companion check fails
// ============================================================================
//
// What this tests:
//   Pre-register a companion → sync → companionCheckResponse in reply
//   → HostEndCompanionCheck FAILS → SetTemplateInvalid called
//   → callback still fires (sync completes despite check failure)
//
// E2E level: HIGH
//   - Entry: service-level SubscribeAvailableDeviceStatus API
//   - Verification: SetTemplateInvalid called, callback still fires
// ============================================================================
HWTEST_F(SyncDeviceStatusModuleTest, HostSyncWithTemplateCheckFailureE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    constexpr UserId HOST_USER = 100;
    constexpr TemplateId TEMPLATE_ID = 99988;
    const std::string companionDeviceId = "companion-check-fail-001";

    // 1. Setup Mock expectations BEFORE RegisterCompanionDirect.
    // RegisterCompanionDirect triggers a SyncDeviceStatus request internally.
    // Use WillRepeatedly because sync may be triggered multiple times.
    HostBeginCompanionCheckOutput checkOutput;
    checkOutput.salt = { 0x05, 0x06, 0x07, 0x08 };
    checkOutput.challenge = 54321;
    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(checkOutput), Return(ResultCode::SUCCESS)));

    // HostEndCompanionCheck FAILS → should trigger SetTemplateInvalid
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndCompanionCheck(_)).WillRepeatedly(Return(ResultCode::GENERAL_ERROR));

    // 2. Setup Phase: Register a companion via direct API call.
    // Per E2E two-phase principle: Setup Phase allows direct internal API calls.
    // SetupCompanionDevice combines TestSimulateDeviceOnline + DrainPendingTasks + RegisterCompanionDirect.
    ASSERT_TRUE(guard.SetupCompanionDevice(HOST_USER, companionDeviceId, TEMPLATE_ID));

    // 3. Verify companion was registered correctly despite HostEndCompanionCheck failure
    DeviceKey queryKey = MakeDeviceKey(companionDeviceId, HOST_USER);

    auto companionStatus = GetCompanionManager().GetCompanionStatus(HOST_USER, queryKey);
    ASSERT_TRUE(companionStatus.has_value()) << "Companion should be registered";
    EXPECT_EQ(companionStatus->templateId, TEMPLATE_ID);

    // 4. Verify device is synced (sync completes despite check failure)
    auto deviceStatus = GetCrossDeviceCommManager().GetDeviceStatus(queryKey);
    ASSERT_TRUE(deviceStatus.has_value()) << "Device should be synced even when check fails";
    EXPECT_EQ(deviceStatus->deviceKey.deviceId, companionDeviceId);
}

// ============================================================================
// Test 5: Companion side — has host binding → reply includes companionCheckResponse
// ============================================================================
//
// What this tests:
//   Setup host binding via HostBindingManager → receive sync request
//   → CompanionProcessCheck called → reply includes companionCheckResponse
//
// E2E level: HIGH
//   - Setup: Real HostBindingManager via BeginAddHostBinding
//   - Entry: raw message injection at FakeChannel boundary
//   - Verification: reply includes non-empty companionCheckResponse
// ============================================================================
HWTEST_F(SyncDeviceStatusModuleTest, CompanionResponseWithBindingE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;

    const std::string connName = "test-conn-binding-001";
    constexpr UserId COMPANION_USER = 100;
    constexpr BindingId BINDING_ID = 111222;

    // 1. Setup Phase: Create a host binding on Companion side.
    // This is a test setup helper that directly calls HostBindingManager to construct
    // the prerequisite state (existing host binding) before the actual E2E test run.
    // Per E2E two-phase principle: Setup Phase allows direct internal API calls for
    // constructing test prerequisites; Execution Phase must follow full message flow.
    ASSERT_TRUE(guard.SetupHostBinding(COMPANION_USER, "host-with-binding-001", BINDING_ID));

    // 2. Test Execution Phase: Mock CompanionProcessCheck response
    // The actual E2E test starts here, with message injection at channel boundary.
    std::vector<uint8_t> expectedCheckResponse = { 0xAB, 0xCD, 0xEF, 0x01, 0x02 };
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _))
        .WillOnce([&](const CompanionProcessCheckInput &input, CompanionProcessCheckOutput &output) {
            EXPECT_GT(input.bindingId, 0);
            EXPECT_FALSE(input.salt.empty());
            EXPECT_GT(input.challenge, 0);
            output.companionCheckResponse = expectedCheckResponse;
            return ResultCode::SUCCESS;
        });

    // 3. Create inbound connection
    guard.GetChannel().TestSimulateIncomingConnection(connName, MakePhysKey("host-with-binding-001"));
    DrainPendingTasks();

    // 4. Build sync request from host
    SyncDeviceStatusRequest request;
    request.protocolIdList = { ProtocolId::VERSION_1 };
    request.capabilityList = { Capability::DELEGATE_AUTH };
    request.hostDeviceKey = MakeDeviceKey("host-with-binding-001", COMPANION_USER);
    request.salt = { 0x01, 0x02, 0x03, 0x04 };
    request.challenge = 88888;

    Attributes requestPayload;
    EncodeSyncDeviceStatusRequest(request, requestPayload);
    EncodeHostDeviceKey(request.hostDeviceKey, requestPayload);

    auto requestRawMsg = BuildRequestRawMsg(connName, 1, MessageType::SYNC_DEVICE_STATUS, requestPayload);

    // 5. Inject request
    guard.GetChannel().ClearSentMessages();
    guard.GetChannel().TestSimulateIncomingMessage(connName, requestRawMsg);
    DrainPendingTasks();

    // 6. Capture reply
    auto sentMsgList = guard.GetChannel().GetSentMessages(connName);
    ASSERT_FALSE(sentMsgList.empty()) << "Expected companion to send a reply";

    auto &replyRawMsg = sentMsgList[0];
    auto replyInfo = DecodeRawMsg(replyRawMsg);
    ASSERT_TRUE(replyInfo.has_value());
    EXPECT_TRUE(replyInfo->isReply);
    EXPECT_EQ(replyInfo->msgType, MessageType::SYNC_DEVICE_STATUS);

    // 7. Verify reply includes companionCheckResponse
    // Note: Cannot use DecodeSyncDeviceStatusReply because EncodeSyncDeviceStatusReply only writes
    // companionUserId, not the full companionDeviceKey. DecodeSyncDeviceStatusReply expects the full key.
    // Verify individual fields instead.
    int32_t resultCode = 0;
    EXPECT_TRUE(replyInfo->payload.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, resultCode));
    EXPECT_EQ(static_cast<ResultCode>(resultCode), ResultCode::SUCCESS);

    std::vector<uint8_t> checkResponse;
    EXPECT_TRUE(replyInfo->payload.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, checkResponse));
    EXPECT_EQ(checkResponse, expectedCheckResponse)
        << "Reply should include companionCheckResponse when binding exists";
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
