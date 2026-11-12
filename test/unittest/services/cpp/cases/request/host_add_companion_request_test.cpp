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

#include "mock_guard.h"
#include "mock_request.h"

#include "add_companion_message.h"
#include "host_add_companion_request.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// Test constants
constexpr ScheduleId SCHEDULE_ID = 1;
const std::vector<uint8_t> FWK_MSG = { 1, 2, 3, 4 };
constexpr uint32_t TOKEN_ID = 123;
constexpr int32_t TEMPLATE_ID = 12345;
const std::string ADDITIONAL_INFO = "";

const DeviceKey COMPANION_DEVICE_KEY = { .deviceId = "companion_device_id", .deviceUserId = 100 };
const DeviceKey HOST_DEVICE_KEY = { .deviceId = "host_device_id", .deviceUserId = 100 };
const DeviceStatus DEVICE_STATUS = {
    .deviceKey = COMPANION_DEVICE_KEY,
    .channelId = ChannelId::SOFTBUS,
    .deviceModelInfo = "TestModel",
    .deviceUserName = "TestUser",
    .deviceName = "TestDevice",
    .protocolId = ProtocolId::VERSION_1,
    .secureProtocolId = SecureProtocolId::DEFAULT,
    .capabilities = { Capability::TOKEN_AUTH },
};
const LocalDeviceProfile LOCAL_PROFILE = {
    .protocols = { ProtocolId::VERSION_1 },
    .hostCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH },
    .companionCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH },
};
// Value reserved for a future VERSION_2 that ProtocolId does not define yet.
constexpr ProtocolId PROTOCOL_VERSION_2 = static_cast<ProtocolId>(2);
constexpr Capability UNKNOWN_CAPABILITY_ID = static_cast<Capability>(999);

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class HostAddCompanionRequestTest : public Test {
protected:
};

HWTEST_F(HostAddCompanionRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetMiscManager(), GetDeviceDeviceSelectResult(123, SelectPurpose::SELECT_ADD_DEVICE, _))
        .WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetMiscManager(), GetDeviceDeviceSelectResult(123, SelectPurpose::SELECT_ADD_DEVICE, _))
        .WillOnce(Return(false));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).Times(1);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    ASSERT_NO_THROW(request->HandleDeviceSelectResult(selectedDevices));
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(false));

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    request->HandleDeviceSelectResult(selectedDevices);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_003, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    std::vector<DeviceKey> selectedDevices = {};
    request->HandleDeviceSelectResult(selectedDevices);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_004, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    // deviceUserId == INVALID_USER_ID must abort before a connection is opened
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).Times(0);

    DeviceKey invalidKey = { .deviceId = "invalid_user_device", .deviceUserId = INVALID_USER_ID };
    std::vector<DeviceKey> selectedDevices = { invalidKey };
    request->HandleDeviceSelectResult(selectedDevices);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

// A stale discovery protocol (e.g. cached before a version rollback) that this build no longer
// supports must fail enrollment before any negotiation starts: proceeding would lead the
// companion to replace its existing binding row with one this build later rejects.
HWTEST_F(HostAddCompanionRequestTest, ValidateAndPinProtocol_RejectsStaleDiscoveryProtocol, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    auto staleStatus = DEVICE_STATUS;
    staleStatus.protocolId = PROTOCOL_VERSION_2; // not in LOCAL_PROFILE.protocols
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(staleStatus)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(LOCAL_PROFILE));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _)).Times(0);

    EXPECT_FALSE(request->ValidateAndPinProtocol(COMPANION_DEVICE_KEY));
    EXPECT_EQ(request->selectedProtocolId_, ProtocolId::INVALID);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(LOCAL_PROFILE));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(
            Invoke([](const HostGetInitKeyNegotiationRequestInput &, HostGetInitKeyNegotiationRequestOutput &output) {
                output.initKeyNegotiationRequest = { 1, 2, 3 };
                return ResultCode::SUCCESS;
            }));
    auto wireCarriesNegotiation = std::make_shared<bool>(false);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::INIT_KEY_NEGOTIATION, _, _))
        .WillOnce(
            Invoke([wireCarriesNegotiation](const std::string &, MessageType, Attributes &msg, OnMessageReply &&) {
                // Emulate the receiving-side MessageRouter stamping the sender identity into the payload
                // (message_router.cpp) before handlers decode it.
                Attributes receivedMsg = msg;
                receivedMsg.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, HOST_DEVICE_KEY.deviceId);
                receivedMsg.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
                    static_cast<int32_t>(HOST_DEVICE_KEY.idType));
                auto decoded = DecodeInitKeyNegotiationRequest(receivedMsg);
                if (decoded.has_value() && decoded->protocolId == ProtocolId::VERSION_1) {
                    *wireCarriesNegotiation = true;
                }
                return true;
            }));

    request->OnConnected();
    EXPECT_TRUE(*wireCarriesNegotiation);
}

// A stale discovery cache announcing the INVALID secure-protocol sentinel must fail before any
// parameter capture or negotiation: proceeding would persist the sentinel as a binding parameter.
HWTEST_F(HostAddCompanionRequestTest, OnConnected_RejectsInvalidSecureProtocolId, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::INVALID)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).Times(0);
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _)).Times(0);

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_003, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(LOCAL_PROFILE));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_004, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(LOCAL_PROFILE));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(
            Invoke([](const HostGetInitKeyNegotiationRequestInput &, HostGetInitKeyNegotiationRequestOutput &output) {
                output.initKeyNegotiationRequest = { 1, 2, 3 };
                return ResultCode::SUCCESS;
            }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::INIT_KEY_NEGOTIATION, _, _))
        .WillOnce(Return(false));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_005, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    auto notNegotiated = DEVICE_STATUS;
    notNegotiated.protocolId = ProtocolId::INVALID;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(notNegotiated)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _)).Times(0);

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

// v3 capability scheme: the C++ capture step no longer intersects capability sets — the
// intersection happens in the security layer over the encrypted binding channel and an
// empty result is legal there. A device announcing capabilities disjoint from the local
// profile therefore must NOT fail OnConnected; the flow proceeds to the security layer.
HWTEST_F(HostAddCompanionRequestTest, OnConnected_006, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    auto noOverlap = DEVICE_STATUS;
    noOverlap.capabilities = { Capability::OBTAIN_TOKEN };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).WillOnce(Return(std::make_optional(noOverlap)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(LOCAL_PROFILE));
    // The flow must reach the security layer (past the capture step) and stop there.
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

// A peer that negotiated a higher protocol version and advertises unknown extra capabilities on
// top of the common ones binds at the higher version; unknown capabilities are filtered out of the
// wire message instead of being forwarded to the secure layer.
HWTEST_F(HostAddCompanionRequestTest, OnConnected_007, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    auto higherVersionPeer = DEVICE_STATUS;
    higherVersionPeer.protocolId = PROTOCOL_VERSION_2;
    higherVersionPeer.capabilities = { Capability::TOKEN_AUTH, UNKNOWN_CAPABILITY_ID };
    auto dualVersionProfile = LOCAL_PROFILE;
    dualVersionProfile.protocols = { ProtocolId::VERSION_1, PROTOCOL_VERSION_2 };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(higherVersionPeer)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(dualVersionProfile));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(
            Invoke([](const HostGetInitKeyNegotiationRequestInput &, HostGetInitKeyNegotiationRequestOutput &output) {
                output.initKeyNegotiationRequest = { 1, 2, 3 };
                return ResultCode::SUCCESS;
            }));
    auto wireCarriesNegotiation = std::make_shared<bool>(false);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::INIT_KEY_NEGOTIATION, _, _))
        .WillOnce(
            Invoke([wireCarriesNegotiation](const std::string &, MessageType, Attributes &msg, OnMessageReply &&) {
                // Emulate the receiving-side MessageRouter stamping the sender identity into the payload
                // (message_router.cpp) before handlers decode it.
                Attributes receivedMsg = msg;
                receivedMsg.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, HOST_DEVICE_KEY.deviceId);
                receivedMsg.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
                    static_cast<int32_t>(HOST_DEVICE_KEY.idType));
                auto decoded = DecodeInitKeyNegotiationRequest(receivedMsg);
                if (decoded.has_value() && decoded->protocolId == PROTOCOL_VERSION_2) {
                    *wireCarriesNegotiation = true;
                }
                return true;
            }));

    request->OnConnected();
    EXPECT_TRUE(*wireCarriesNegotiation);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_008, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _)).Times(0);

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    LocalDeviceProfile profile = { .protocols = { ProtocolId::VERSION_1 },
        .hostCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH } };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile));
    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _, _))
        .WillOnce(Invoke([&profile](const BeginAddCompanionParams &params, std::vector<uint8_t> &out,
                             SelectedAlgorithms &selectedAlgorithms) {
            // The host capability offer and protocol priority list travel with
            // the begin-add params into the security layer (they are carried
            // inside the encrypted binding request for companion recomputation).
            EXPECT_EQ(params.hostCapabilityList, profile.hostCapabilities);
            EXPECT_EQ(params.hostProtocolList, profile.protocols);
            out = { 4, 5, 6 };
            selectedAlgorithms.kaAlgorithm = 1;
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(true));

    ASSERT_NO_THROW(request->HandleInitKeyNegotiationReply(reply));
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    request->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_003, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    request->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_004, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_005, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _, _))
        .WillOnce(Invoke(
            [](const BeginAddCompanionParams &, std::vector<uint8_t> &out, SelectedAlgorithms &selectedAlgorithms) {
                out = { 4, 5, 6 };
                selectedAlgorithms.kaAlgorithm = 1;
                return ResultCode::SUCCESS;
            }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::BEGIN_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(false));

    request->HandleInitKeyNegotiationReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([](const EndAddCompanionInput &, EndAddCompanionOutput &output) {
            output.fwkMsg = { 7, 8, 9 };
            output.templateId = TEMPLATE_ID;
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::END_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(true));

    ASSERT_NO_THROW(request->HandleBeginAddHostBindingReply(reply));
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    request->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_003, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    request->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_004, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->HandleBeginAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleBeginAddHostBindingReply_005, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    Attributes reply;
    BeginAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeBeginAddHostBindingReply(replyMsg, reply);

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([](const EndAddCompanionInput &, EndAddCompanionOutput &output) {
            output.fwkMsg = { 7, 8, 9 };
            output.templateId = TEMPLATE_ID;
            return ResultCode::SUCCESS;
        }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, MessageType::END_ADD_HOST_BINDING, _, _))
        .WillOnce(Return(false));

    ASSERT_NO_THROW(request->HandleBeginAddHostBindingReply(reply));
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->templateId_ = TEMPLATE_ID;

    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAuthAtl(_, _, true)).WillOnce(Return(true));

    Attributes reply;
    EndAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS };
    EncodeEndAddHostBindingReply(replyMsg, reply);

    request->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_002, TestSize.Level0)
{
    MockGuard guard;

    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    Attributes reply;
    request->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_003, TestSize.Level0)
{
    // Token distribution failed but enrollment succeeded - should complete with success
    MockGuard guard;

    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    Attributes reply;
    EndAddHostBindingReply replyMsg = { .result = ResultCode::GENERAL_ERROR };
    EncodeEndAddHostBindingReply(replyMsg, reply);

    request->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    request->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;

    auto callbackCalled = std::make_shared<bool>(false);
    auto callback = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->needCancelCompanionAdd_ = true;

    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelAddCompanion(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithError_003, TestSize.Level0)
{
    MockGuard guard;

    int callbackCount = 0;
    auto callback = [&callbackCount](ResultCode result, const std::vector<uint8_t> &) {
        callbackCount++;
        // After enrollment succeeded, a later token-distribution failure must still complete with success.
        EXPECT_EQ(result, ResultCode::SUCCESS);
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->enrollmentSucceeded_ = true;

    // Routes through the enrollmentSucceeded_ success path, then a re-entrant
    // terminal call must be suppressed by AcquireCompletion: the framework callback fires exactly once.
    request->CompleteWithError(ResultCode::GENERAL_ERROR);
    request->CompleteWithSuccess();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(callbackCount, 1);
}

HWTEST_F(HostAddCompanionRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;

    auto callbackCalled = std::make_shared<bool>(false);
    auto receivedData = std::make_shared<std::vector<uint8_t>>();
    auto callback = [&callbackCalled, &receivedData](ResultCode result, const std::vector<uint8_t> &data) {
        *callbackCalled = true;
        *receivedData = data;
        EXPECT_EQ(result, ResultCode::SUCCESS);
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    request->CompleteWithSuccess();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostAddCompanionRequestTest, EndAddCompanion_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);

    DeviceStatus deviceStatus;
    deviceStatus.deviceModelInfo = "model";
    deviceStatus.deviceUserName = "user";
    deviceStatus.deviceName = "name";
    deviceStatus.deviceSubProfileName = "subProfile";
    deviceStatus.supportedBusinessIds = { BusinessId::DEFAULT };
    deviceStatus.capabilities = { Capability::TOKEN_AUTH };
    request->selectedProtocolId_ = ProtocolId::VERSION_1;

    auto persistedProtocolId = std::make_shared<ProtocolId>(ProtocolId::INVALID);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([persistedProtocolId](const EndAddCompanionInput &input, EndAddCompanionOutput &output) {
            *persistedProtocolId = input.companionStatus.enrolledProtocolId;
            EXPECT_EQ(input.supportedBusinessIds, std::vector<BusinessId> { BusinessId::DEFAULT });
            EXPECT_EQ(input.companionStatus.deviceModelInfo, "model");
            EXPECT_EQ(input.companionStatus.deviceUserName, "user");
            EXPECT_EQ(input.companionStatus.deviceName, "name");
            EXPECT_EQ(input.companionStatus.deviceSubProfileName, "subProfile");
            EXPECT_EQ(input.companionStatus.companionDeviceKey, COMPANION_DEVICE_KEY);
            EXPECT_EQ(input.companionStatus.enrolledProtocolId, ProtocolId::VERSION_1);
            EXPECT_TRUE(input.companionStatus.isValid);
            output.templateId = TEMPLATE_ID;
            return ResultCode::SUCCESS;
        }));

    BeginAddHostBindingReply reply;
    std::vector<uint8_t> fwkMsg;

    ResultCode result = request->EndAddCompanion(reply, fwkMsg);

    EXPECT_EQ(result, ResultCode::SUCCESS);
    EXPECT_EQ(*persistedProtocolId, ProtocolId::VERSION_1);
    EXPECT_EQ(request->templateId_, TEMPLATE_ID);
}

HWTEST_F(HostAddCompanionRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    ASSERT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, {}));
}

HWTEST_F(HostAddCompanionRequestTest, InvokeCallback_002_DoubleInvokeProtection, TestSize.Level0)
{
    MockGuard guard;

    auto callbackCalled = std::make_shared<int>(0);
    auto callback = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { ++*callbackCalled; };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    // First call should succeed and null out the callback.
    request->InvokeCallback(ResultCode::SUCCESS, {});
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*callbackCalled, 1);

    // Second call should be silently ignored (callback already moved out).
    request->InvokeCallback(ResultCode::GENERAL_ERROR, {});
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*callbackCalled, 1);
}

HWTEST_F(HostAddCompanionRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 1);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostAddCompanionRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::COMPANION_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostAddCompanionRequestTest, ParseAdditionalInfo_001, TestSize.Level0)
{
    // Test parsing additionalInfo with enabled_business_ids
    MockGuard guard;

    // Create fwkMsg with additionalInfo
    std::string additionalInfo = R"({"enabled_business_ids":[1,2,3]})";
    FwkAttribute fwkAttr;
    fwkAttr.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, additionalInfo);
    auto fwkMsg = fwkAttr.Serialize();

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, fwkMsg, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    // Parsing is done in constructor, and stored in request
    // The test passes if no exception is thrown
    EXPECT_TRUE(request != nullptr);
}

HWTEST_F(HostAddCompanionRequestTest, ParseAdditionalInfo_002, TestSize.Level0)
{
    // Test parsing additionalInfo with empty string
    MockGuard guard;

    std::string additionalInfo = "";
    FwkAttribute fwkAttr;
    fwkAttr.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, additionalInfo);
    auto fwkMsg = fwkAttr.Serialize();

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, fwkMsg, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_TRUE(request != nullptr);
}

HWTEST_F(HostAddCompanionRequestTest, ParseAdditionalInfo_003, TestSize.Level0)
{
    // Test parsing additionalInfo with invalid JSON
    MockGuard guard;

    std::string additionalInfo = "not a valid json";
    FwkAttribute fwkAttr;
    fwkAttr.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, additionalInfo);
    auto fwkMsg = fwkAttr.Serialize();

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, fwkMsg, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_TRUE(request != nullptr);
}

HWTEST_F(HostAddCompanionRequestTest, ParseAdditionalInfo_004, TestSize.Level0)
{
    // Test parsing additionalInfo with enabled_business_ids containing invalid values
    MockGuard guard;

    std::string additionalInfo = R"({"enabled_business_ids":["string", null, 10000]})";
    FwkAttribute fwkAttr;
    fwkAttr.SetStringValue(FwkAttributeKey::ATTR_ADDITIONAL_INFO, additionalInfo);
    auto fwkMsg = fwkAttr.Serialize();

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, fwkMsg, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_TRUE(request != nullptr);
}

// The device list offered to SELECT_ADD_DEVICE and the supportedBusinessIds cross-check both come
// from the synced device status, so the peer must be brought online before OnStart runs.
HWTEST_F(HostAddCompanionRequestTest, RequireSyncedDevice_IsTrue, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_TRUE(request->RequireSyncedDevice());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
