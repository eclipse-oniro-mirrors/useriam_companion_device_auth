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
#include <optional>

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
const std::vector<uint8_t> ICON_DATA = { 1, 2, 3, 4, 5 };

const DeviceKey COMPANION_DEVICE_KEY = { .deviceId = "companion_device_id", .deviceUserId = 100 };
const DeviceKey HOST_DEVICE_KEY = { .deviceId = "host_device_id", .deviceUserId = 100 };
const std::string HOST_USER_ICON_DIR =
    "/data/service/el1/" + std::to_string(HOST_DEVICE_KEY.deviceUserId) + "/useriam/companion_device_auth/icons";
const DeviceStatus DEVICE_STATUS = {
    .deviceKey = COMPANION_DEVICE_KEY,
    .channelId = ChannelId::SOFTBUS,
    .deviceModelInfo = "TestModel",
    .deviceUserName = "TestUser",
    .deviceName = "TestDevice",
    .selectedProtocolId = ProtocolId::VERSION_1,
    .freshBindingProtocolId = ProtocolId::VERSION_1,
    .secureProtocolId = SecureProtocolId::DEFAULT,
    .capabilities = { Capability::TOKEN_AUTH },
};
const LocalDeviceProfile LOCAL_PROFILE = {
    .hostProtocols = { ProtocolId::VERSION_1 },
    .hostCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH },
    .companionCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH },
};

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

    // Selection reads the policy-vouched device status directly and opens the connection;
    // the request drives no explicit pairing sync round.
    DeviceStatus syncedStatus {};
    syncedStatus.selectedProtocolId = ProtocolId::VERSION_2;
    syncedStatus.freshBindingProtocolId = ProtocolId::VERSION_2;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(syncedStatus)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), EnsureDeviceSynced(_, _)).Times(0);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).Times(1);

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    ASSERT_NO_THROW(request->HandleDeviceSelectResult(selectedDevices, std::nullopt));
}

HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_002, TestSize.Level0)
{
    MockGuard guard;

    // A peer whose status the policy layer does not hold yet (never synced / not adopted)
    // fails the selection cleanly; recovery is owned by the policy layer's own sync rounds.
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const std::vector<uint8_t> &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).Times(0);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), ResyncDevice(_)).Times(0);

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    request->HandleDeviceSelectResult(selectedDevices, std::nullopt);

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
    request->HandleDeviceSelectResult(selectedDevices, std::nullopt);

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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), EnsureDeviceSynced(_, _)).Times(0);

    DeviceKey invalidKey = { .deviceId = "invalid_user_device", .deviceUserId = INVALID_USER_ID };
    std::vector<DeviceKey> selectedDevices = { invalidKey };
    request->HandleDeviceSelectResult(selectedDevices, std::nullopt);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

// The pairing is a fresh binding: it consumes the discovery-view candidate (freshBindingProtocolId,
// recomputed each sync from full support lists) into selectedProtocolId_ and carries it on the wire
// to the companion, ignoring the binding view (selectedProtocolId) that pins the old credential.
HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_StatusCarriesFreshBindingProtocol, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    DeviceStatus syncedStatus {};
    syncedStatus.selectedProtocolId = ProtocolId::VERSION_1;
    syncedStatus.freshBindingProtocolId = ProtocolId::VERSION_2;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(syncedStatus)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    request->HandleDeviceSelectResult(selectedDevices, std::nullopt);

    auto dualVersionProfile = LOCAL_PROFILE;
    dualVersionProfile.hostProtocols = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
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
                if (decoded.has_value() && decoded->selectedProtocolId == ProtocolId::VERSION_2) {
                    *wireCarriesNegotiation = true;
                }
                return true;
            }));

    request->OnConnected();
    EXPECT_TRUE(*wireCarriesNegotiation);
}

// A policy-vouched device status without a valid fresh-binding protocol must fail the pairing
// flow instead of opening a connection, even while the binding view still carries a value;
// no resync is armed by the request itself.
HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_InvalidCachedProtocolFails, TestSize.Level0)
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

    DeviceStatus staleStatus {};
    staleStatus.selectedProtocolId = ProtocolId::VERSION_1;
    staleStatus.freshBindingProtocolId = ProtocolId::INVALID;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(staleStatus)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).Times(0);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), ResyncDevice(_)).Times(0);

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    request->HandleDeviceSelectResult(selectedDevices, std::nullopt);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

// A round payload this build no longer supports must fail enrollment before any negotiation
// starts, or the companion would replace its binding with one this build rejects.
HWTEST_F(HostAddCompanionRequestTest, ValidateAndSelectProtocol_RejectsStaleDiscoveryProtocol, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    request->selectedProtocolId_ = ProtocolId::VERSION_2; // not in LOCAL_PROFILE.hostProtocols
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).Times(0);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(LOCAL_PROFILE));
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _)).Times(0);

    EXPECT_FALSE(request->ValidateAndSelectProtocol());
    EXPECT_EQ(request->selectedProtocolId_, ProtocolId::INVALID);
}

// Selected protocol comes only from the pairing round's payload: with no payload there is
// nothing to select, and the device-level cache must not be consulted as a fallback.
HWTEST_F(HostAddCompanionRequestTest, ValidateAndSelectProtocol_MissingRoundPayloadFails, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).Times(0);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).Times(0);
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _)).Times(0);

    EXPECT_FALSE(request->ValidateAndSelectProtocol());
    EXPECT_EQ(request->selectedProtocolId_, ProtocolId::INVALID);
}

HWTEST_F(HostAddCompanionRequestTest, ValidateAndSelectProtocol_AcceptsRoundPayload, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    request->selectedProtocolId_ = ProtocolId::VERSION_1;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).Times(0);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(LOCAL_PROFILE));

    EXPECT_TRUE(request->ValidateAndSelectProtocol());
    EXPECT_EQ(request->selectedProtocolId_, ProtocolId::VERSION_1);
}

HWTEST_F(HostAddCompanionRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->selectedProtocolId_ = ProtocolId::VERSION_1;

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).Times(0);
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
                if (decoded.has_value() && decoded->selectedProtocolId == ProtocolId::VERSION_1) {
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
    request->selectedProtocolId_ = ProtocolId::VERSION_1;

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
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
    request->selectedProtocolId_ = ProtocolId::VERSION_1;

    // Need to open connection first to set connectionName_
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
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

// The pairing round never delivered a negotiated protocol, so protocol capture must fail
// instead of falling back to the device-level cache.
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
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_)).Times(0);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).Times(0);
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _)).Times(0);

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

// Capability intersection happens in the security layer, and an empty result is legal there:
// a device announcing capabilities disjoint from the local profile must not fail OnConnected.
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
    request->selectedProtocolId_ = ProtocolId::VERSION_1;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillRepeatedly(Return(LOCAL_PROFILE));
    // The flow must reach the security layer (past the capture step) and stop there.
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetInitKeyNegotiationRequest(_, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->OnConnected();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

// A peer advertising unknown extra capabilities on top of the common ones still binds;
// unknown values are filtered out of the wire message instead of reaching the secure layer.
HWTEST_F(HostAddCompanionRequestTest, OnConnected_007, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->selectedProtocolId_ = ProtocolId::VERSION_2;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).WillOnce(Return(true));
    ASSERT_TRUE(request->OpenConnection());

    auto dualVersionProfile = LOCAL_PROFILE;
    dualVersionProfile.hostProtocols = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(std::make_optional(SecureProtocolId::DEFAULT)));
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
                if (decoded.has_value() && decoded->selectedProtocolId == ProtocolId::VERSION_2) {
                    *wireCarriesNegotiation = true;
                }
                return true;
            }));

    request->OnConnected();
    EXPECT_TRUE(*wireCarriesNegotiation);
}

HWTEST_F(HostAddCompanionRequestTest, HandleInitKeyNegotiationReply_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->selectedProtocolId_ = ProtocolId::VERSION_1;

    Attributes reply;
    InitKeyNegotiationReply replyMsg = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    EncodeInitKeyNegotiationReply(replyMsg, reply);

    LocalDeviceProfile profile = { .hostProtocols = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 },
        .hostCapabilities = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH } };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _, _))
        .WillOnce(Invoke([&profile](const BeginAddCompanionParams &params, std::vector<uint8_t> &out,
                             std::vector<SelectedAlgorithms> &selectedAlgorithmsList) {
            // The broadcast carries the selected protocol alone (not the full capability-table
            // list), keeping the companion's recompute anchored to the same value it was told.
            EXPECT_EQ(params.hostCapabilityList, profile.hostCapabilities);
            EXPECT_EQ(params.hostProtocolIdList, std::vector<ProtocolId> { ProtocolId::VERSION_1 });
            out = { 4, 5, 6 };
            selectedAlgorithmsList.push_back(SelectedAlgorithms { .kaAlgorithm = 1 });
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

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
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

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(DEVICE_STATUS)));
    EXPECT_CALL(guard.GetCompanionManager(), BeginAddCompanion(_, _, _))
        .WillOnce(Invoke([](const BeginAddCompanionParams &, std::vector<uint8_t> &out,
                             std::vector<SelectedAlgorithms> &selectedAlgorithmsList) {
            out = { 4, 5, 6 };
            selectedAlgorithmsList.push_back(SelectedAlgorithms { .kaAlgorithm = 1 });
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
    // The activation gate reads the negotiated list carried by the enrollment reply
    // (in-memory mirror is not readable before the template is added to IDM).
    request->enrolledCapabilityList_ = { Capability::TOKEN_AUTH, Capability::DELEGATE_AUTH };

    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAuthAtl(_, _, true)).WillOnce(Return(true));

    Attributes reply;
    EndAddHostBindingReply replyMsg = { .result = ResultCode::SUCCESS };
    EncodeEndAddHostBindingReply(replyMsg, reply);

    request->HandleEndAddHostBindingReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostAddCompanionRequestTest, HandleEndAddHostBindingReply_006_TokenAuthNotNegotiated, TestSize.Level0)
{
    // TokenAuth not in the negotiated capability list: token activation is skipped,
    // but the enrollment still completes with success.
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
    // Negotiated list without TokenAuth (an empty list behaves the same): activation must be skipped.
    request->enrolledCapabilityList_ = { Capability::DELEGATE_AUTH };

    EXPECT_CALL(guard.GetCompanionManager(), SetCompanionTokenAuthAtl(_, _, true)).Times(0);

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

// A request at the enrollment end: the peer is known and the protocol is selected.
std::shared_ptr<HostAddCompanionRequest> MakeRequestAtEnrollEnd()
{
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->hostDeviceKey_ = HOST_DEVICE_KEY;
    request->selectedProtocolId_ = ProtocolId::VERSION_1;
    return request;
}

// The peer is in range and its binding gets persisted.
void ExpectEnrollEndToPersist(MockGuard &guard)
{
    DeviceStatus deviceStatus;
    deviceStatus.supportedBusinessIds = { BusinessId::DEFAULT };
    deviceStatus.capabilities = { Capability::TOKEN_AUTH };
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(guard.GetCompanionManager(), EndAddCompanion(_, _))
        .WillOnce(Invoke([](const EndAddCompanionInput &, EndAddCompanionOutput &output) {
            output.templateId = TEMPLATE_ID;
            return ResultCode::SUCCESS;
        }));
}

// The icon picked during device selection is stored once the binding is persisted, under the icon
// directory of the host user.
HWTEST_F(HostAddCompanionRequestTest, EndAddCompanion_WithIcon_StoresItThroughFileStorage, TestSize.Level0)
{
    MockGuard guard;
    ExpectEnrollEndToPersist(guard);
    auto request = MakeRequestAtEnrollEnd();
    ASSERT_NE(request, nullptr);
    request->companionIcon_ = CompanionIcon { "watch.png", ICON_DATA };

    BeginAddHostBindingReply reply;
    std::vector<uint8_t> fwkMsg;
    EXPECT_EQ(request->EndAddCompanion(reply, fwkMsg), ResultCode::SUCCESS);

    EXPECT_EQ(guard.GetFileStorageAdapter().GetSavedFiles(),
        std::vector<MockFileStorageAdapter::SavedFile>({ { HOST_USER_ICON_DIR, "watch.png", ICON_DATA } }));
}

// The binding is already persisted when the icon is stored: a failing write leaves the enrollment
// result alone.
HWTEST_F(HostAddCompanionRequestTest, EndAddCompanion_IconStoreFailure_KeepsEnrollmentResult, TestSize.Level0)
{
    MockGuard guard;
    ExpectEnrollEndToPersist(guard);
    guard.GetFileStorageAdapter().SetSaveResult(ResultCode::GENERAL_ERROR);
    auto request = MakeRequestAtEnrollEnd();
    ASSERT_NE(request, nullptr);
    request->companionIcon_ = CompanionIcon { "watch.png", ICON_DATA };

    BeginAddHostBindingReply reply;
    std::vector<uint8_t> fwkMsg;
    EXPECT_EQ(request->EndAddCompanion(reply, fwkMsg), ResultCode::SUCCESS);
    EXPECT_EQ(request->templateId_, TEMPLATE_ID);
}

HWTEST_F(HostAddCompanionRequestTest, EndAddCompanion_WithoutIcon_StoresNothing, TestSize.Level0)
{
    MockGuard guard;
    ExpectEnrollEndToPersist(guard);
    auto request = MakeRequestAtEnrollEnd();
    ASSERT_NE(request, nullptr);

    BeginAddHostBindingReply reply;
    std::vector<uint8_t> fwkMsg;
    EXPECT_EQ(request->EndAddCompanion(reply, fwkMsg), ResultCode::SUCCESS);
    EXPECT_TRUE(guard.GetFileStorageAdapter().GetSavedFiles().empty());
}

// The selection context carries the companion icon, kept until the enrollment end stores it.
HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_WithIconContext_KeepsIcon, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    // The device is in range with a usable protocol; the icon in the context is kept for the
    // enrollment end.
    DeviceStatus syncedStatus {};
    syncedStatus.selectedProtocolId = ProtocolId::VERSION_1;
    syncedStatus.freshBindingProtocolId = ProtocolId::VERSION_1;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetDeviceStatus(_))
        .WillOnce(Return(std::make_optional(syncedStatus)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), EnsureDeviceSynced(_, _)).Times(0);
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).Times(1);

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    std::string contextJson = R"({"icon_file_name":"watch.png","icon_data":"AQIDBAU="})";
    std::vector<uint8_t> context(contextJson.begin(), contextJson.end());
    ASSERT_NO_THROW(request->HandleDeviceSelectResult(selectedDevices, context));

    ASSERT_TRUE(request->companionIcon_.has_value());
    EXPECT_EQ(request->companionIcon_->fileName, "watch.png");
    EXPECT_EQ(request->companionIcon_->data, ICON_DATA);
}

// An icon that cannot be parsed fails the request before any connection is opened.
HWTEST_F(HostAddCompanionRequestTest, HandleDeviceSelectResult_WithInvalidIconContext_Fails, TestSize.Level0)
{
    MockGuard guard;

    ResultCode received = ResultCode::SUCCESS;
    auto callback = [&received](ResultCode result, const std::vector<uint8_t> &) { received = result; };
    auto request =
        std::make_shared<HostAddCompanionRequest>(SCHEDULE_ID, FWK_MSG, TOKEN_ID, ADDITIONAL_INFO, std::move(callback));

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _)).Times(0);

    std::vector<DeviceKey> selectedDevices = { COMPANION_DEVICE_KEY };
    std::string contextJson = R"({"icon_file_name":"a/b.png","icon_data":"AQIDBAU="})";
    std::vector<uint8_t> context(contextJson.begin(), contextJson.end());
    request->HandleDeviceSelectResult(selectedDevices, context);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(received, ResultCode::INVALID_PARAMETERS);
    EXPECT_FALSE(request->companionIcon_.has_value());
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
