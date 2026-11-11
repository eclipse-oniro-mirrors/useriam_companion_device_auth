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

#include "companion_sync_device_status_handler.h"
#include "error_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_200 = 200;
constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_MINUS_1 = -1;
// Value reserved for a future VERSION_2 that ProtocolId does not define yet.
constexpr ProtocolId PROTOCOL_VERSION_2 = static_cast<ProtocolId>(2);
constexpr Capability UNSUPPORTED_CAPABILITY_ID = static_cast<Capability>(999);

class CompanionSyncDeviceStatusHandlerTest : public Test {
protected:
    std::unique_ptr<CompanionSyncDeviceStatusHandler> handler_;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = INT32_100 };
    LocalDeviceProfile profile_ = { .protocols = { ProtocolId::VERSION_1 },
        .companionSecureProtocolId = SecureProtocolId::DEFAULT,
        .companionCapabilities = { Capability::TOKEN_AUTH } };
    DeviceStatus hostDeviceStatus_ = { .deviceKey = hostDeviceKey_,
        .channelId = ChannelId::SOFTBUS,
        .deviceModelInfo = "TestModel",
        .deviceUserName = "TestUser",
        .deviceName = "TestDevice",
        .protocolId = ProtocolId::VERSION_1,
        .secureProtocolId = SecureProtocolId::DEFAULT };
    HostBindingStatus hostBindingStatus_ = { .bindingId = 1,
        .companionUserKey = UserKey { INT32_200, INVALID_SUB_PROFILE_ID },
        .hostDeviceStatus = hostDeviceStatus_,
        .enrolledProtocolId = ProtocolId::VERSION_1 };
};

// Mocks the common lookup chain used by HandleRequest for a bound host: active user, local profile,
// binding status, and a succeeding CompanionProcessCheck that captures its input for assertions.
void ExpectBoundSyncRequestMocks(MockGuard &guard, const LocalDeviceProfile &profile,
    const HostBindingStatus &hostBindingStatus, CompanionProcessCheckInput &capturedInput)
{
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _))
        .WillOnce(Invoke([&capturedInput](const auto &input, auto &output) {
            capturedInput = input;
            output.companionCheckResponse = { 1 };
            return ResultCode::SUCCESS;
        }));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _))
        .WillOnce(Invoke([](const CompanionProcessCheckInput &, CompanionProcessCheckOutput &output) {
            output.companionCheckResponse = { 1 };
            return ResultCode::SUCCESS;
        }));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_MINUS_1, INVALID_SUB_PROFILE_ID }));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_004, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _)).Times(0);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
    std::vector<uint8_t> proof;
    ASSERT_TRUE(reply.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, proof));
    EXPECT_TRUE(proof.empty());
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_CheckFailurePropagates, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    Attributes reply;
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    auto decoded = DecodeSyncDeviceStatusReply(reply);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_EmptyProofDespiteSuccessFails, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    Attributes reply;
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    auto decoded = DecodeSyncDeviceStatusReply(reply);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->result, ResultCode::GENERAL_ERROR);
}

// A peer-build limitation (cannot interpret the enrolled secure protocol) is not a divergence: the
// code must reach the host so it keeps the binding instead of treating an empty check as failure.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_SecureProtocolNotSupportedPropagates, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _))
        .WillOnce(Return(ResultCode::SECURE_PROTOCOL_NOT_SUPPORTED));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SECURE_PROTOCOL_NOT_SUPPORTED));
}

// Discovery announces the current enrollment secure protocol; the security agent independently
// uses the persisted protocol to frame the existing binding's proof.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_BoundAnnouncesCurrentEnrollmentSecureProtocol,
    TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    LocalDeviceProfile profile = profile_;
    // Decode enforces only the field's presence; which secure protocol values the host can
    // consume is judged inside its Rust security layer. The echo is verified with DEFAULT, the
    // only value the current host build accepts.
    constexpr auto newSecureProtocol = SecureProtocolId::DEFAULT;
    profile.companionSecureProtocolId = newSecureProtocol;
    HostBindingStatus bindingStatus = hostBindingStatus_;

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(bindingStatus)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _))
        .WillOnce(Invoke([](const CompanionProcessCheckInput &, CompanionProcessCheckOutput &output) {
            output.companionCheckResponse = { 1 };
            return ResultCode::SUCCESS;
        }));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    // The identifier attributes are injected by the transport layer, not by the message encoder;
    // add them before decoding, mirroring what the receiving side sees on the wire.
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    auto decoded = DecodeSyncDeviceStatusReply(reply);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->secureProtocolId, newSecureProtocol);
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_006, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName()).WillOnce(Return(std::nullopt));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_007, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(DeviceIdType::UNKNOWN));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, "wrong_device_id");

    // Negotiation runs before the reply builder and needs a non-empty local protocol list; the
    // MockGuard default profile carries none, which would fail as PROTOCOL_NEGOTIATION_FAILED.
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_EncodesUserTypePrefix, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("private"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);

    std::string deviceUserName;
    EXPECT_TRUE(reply.GetStringValue(Attributes::ATTR_CDA_SA_USER_NAME, deviceUserName));
    EXPECT_EQ(deviceUserName, "private:TestUser");
}

// A successful sync publishes PEER_SYNCED carrying the host's physical key, which feeds
// the synced-peer registry that gates resync fan-out.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_PublishesPeerSyncedEvent, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    // Exactly one profile pull happens per request: negotiation fetches it once and passes it down
    // to both the reply builder and the companion check.
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    EventData publishedData;
    EXPECT_CALL(guard.GetEventBus(), Publish(EventType::PEER_SYNCED, _))
        .WillOnce(Invoke([&publishedData](EventType, const EventData &data) { publishedData = data; }));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);

    int32_t replyResult = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));

    Attributes payload(publishedData);
    std::string deviceId;
    int32_t idType = 0;
    EXPECT_TRUE(payload.GetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, deviceId));
    EXPECT_EQ(deviceId, hostDeviceKey_.deviceId);
    EXPECT_TRUE(payload.GetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, idType));
    EXPECT_EQ(idType, static_cast<int32_t>(hostDeviceKey_.idType));
}

// A higher-version host offering only protocols this device does not support must fail negotiation
// explicitly instead of silently proceeding; the error reply lets the host map to a retryable
// failure without invalidating its binding.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_ProtocolNegotiationFailed, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { PROTOCOL_VERSION_2 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _)).Times(0);

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::PROTOCOL_NEGOTIATION_FAILED));
}

// A higher-version host offering a mix of known and unknown protocols must be answered over the
// intersection: only negotiated protocol entries reach the secure layer, never the raw offer.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_NegotiatesIntersection, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);
    hostBindingStatus_.enrolledProtocolId = ProtocolId::VERSION_1;

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1, PROTOCOL_VERSION_2 },
        .capabilityList = { Capability::TOKEN_AUTH, UNSUPPORTED_CAPABILITY_ID },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    CompanionProcessCheckInput capturedInput = {};
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _))
        .WillOnce(Invoke([&capturedInput](const auto &input, auto &output) {
            capturedInput = input;
            output.companionCheckResponse = { 1 };
            return ResultCode::SUCCESS;
        }));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
    EXPECT_EQ(capturedInput.protocolList, std::vector<uint16_t> { static_cast<uint16_t>(ProtocolId::VERSION_1) });
    EXPECT_EQ(capturedInput.companionCapabilityList,
        std::vector<uint16_t> { static_cast<uint16_t>(Capability::TOKEN_AUTH) });
    std::vector<uint8_t> proof;
    ASSERT_TRUE(reply.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, proof));
    EXPECT_FALSE(proof.empty());

    std::vector<uint16_t> outerCapabilityList;
    ASSERT_TRUE(reply.GetUint16ArrayValue(Attributes::ATTR_CDA_SA_CAPABILITY_LIST, outerCapabilityList));
    EXPECT_EQ(outerCapabilityList, std::vector<uint16_t> { static_cast<uint16_t>(Capability::TOKEN_AUTH) });
}

// A bound host re-validates at the version its binding was enrolled with: even when both sides
// support a higher common version, the selection is pinned to the enrolled one and the reply
// echoes exactly it, so the host's own pick cannot drift to a newer version.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_PinsSelectionToEnrolledProtocol, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    LocalDeviceProfile profile = { .protocols = { ProtocolId::VERSION_1, PROTOCOL_VERSION_2 },
        .companionSecureProtocolId = SecureProtocolId::DEFAULT,
        .companionCapabilities = { Capability::TOKEN_AUTH } };
    HostBindingStatus hostBindingStatus = hostBindingStatus_;
    hostBindingStatus.enrolledProtocolId = ProtocolId::VERSION_1;

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1, PROTOCOL_VERSION_2 },
        .capabilityList = { Capability::TOKEN_AUTH, UNSUPPORTED_CAPABILITY_ID },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    CompanionProcessCheckInput capturedInput = {};
    ExpectBoundSyncRequestMocks(guard, profile, hostBindingStatus, capturedInput);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
    EXPECT_EQ(capturedInput.protocolList, std::vector<uint16_t> { static_cast<uint16_t>(ProtocolId::VERSION_1) });

    // The identifier attributes are injected by the transport layer, not by the message encoder;
    // add them before decoding, mirroring what the receiving side sees on the wire.
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    auto decodedReply = DecodeSyncDeviceStatusReply(reply);
    EXPECT_TRUE(decodedReply.has_value());
    EXPECT_EQ(decodedReply->protocolIdList, std::vector<ProtocolId> { ProtocolId::VERSION_1 });
    EXPECT_EQ(decodedReply->capabilityList, std::vector<Capability> { Capability::TOKEN_AUTH });
    EXPECT_EQ(capturedInput.companionCapabilityList,
        std::vector<uint16_t> { static_cast<uint16_t>(Capability::TOKEN_AUTH) });
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, NegotiateSyncParameters_UsesEnrolledVersionFromFullOffer,
    TestSize.Level0)
{
    auto handler = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler, nullptr);
    LocalDeviceProfile profile = profile_;
    profile.protocols = { PROTOCOL_VERSION_2, ProtocolId::VERSION_1 };
    SyncDeviceStatusRequest request;
    request.protocolIdList = profile.protocols;
    request.capabilityList = profile.companionCapabilities;
    ErrorGuard errorGuard([](ResultCode) {});
    for (auto enrolled : profile.protocols) {
        auto binding = hostBindingStatus_;
        binding.enrolledProtocolId = enrolled;
        auto result = handler->NegotiateSyncParameters(request, profile, binding, errorGuard);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(*result, std::vector<ProtocolId> { enrolled });
    }
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, NegotiateSyncParameters_DoesNotReplaceUnavailableEnrollment,
    TestSize.Level0)
{
    auto handler = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler, nullptr);
    auto binding = hostBindingStatus_;
    binding.enrolledProtocolId = PROTOCOL_VERSION_2;
    LocalDeviceProfile profile = profile_;
    profile.protocols = { ProtocolId::VERSION_1, PROTOCOL_VERSION_2 };
    SyncDeviceStatusRequest request;
    request.protocolIdList = { ProtocolId::VERSION_1 };
    request.capabilityList = profile.companionCapabilities;
    ResultCode error = GENERAL_ERROR;
    {
        ErrorGuard errorGuard([&error](ResultCode code) { error = code; });
        EXPECT_FALSE(handler->NegotiateSyncParameters(request, profile, binding, errorGuard).has_value());
    }
    EXPECT_EQ(error, PROTOCOL_NEGOTIATION_FAILED);
    request.protocolIdList = profile.protocols;
    {
        ErrorGuard errorGuard([&error](ResultCode code) { error = code; });
        EXPECT_FALSE(handler->NegotiateSyncParameters(request, profile_, binding, errorGuard).has_value());
    }
    EXPECT_EQ(error, PROTOCOL_NEGOTIATION_FAILED);
}

// The enroll path always persists a real protocol, so INVALID marks a corrupted binding row:
// it must be rejected against any offer instead of re-negotiating from what the host announces
// (a corrupt row must not drift to the offer; re-enrollment heals it).
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, NegotiateSyncParameters_RejectsBindingWithoutEnrolledProtocol,
    TestSize.Level0)
{
    auto handler = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler, nullptr);
    auto binding = hostBindingStatus_;
    binding.enrolledProtocolId = ProtocolId::INVALID;
    SyncDeviceStatusRequest request;
    request.protocolIdList = profile_.protocols;
    request.capabilityList = profile_.companionCapabilities;
    ResultCode error = GENERAL_ERROR;
    {
        ErrorGuard errorGuard([&error](ResultCode code) { error = code; });
        EXPECT_FALSE(handler->NegotiateSyncParameters(request, profile_, binding, errorGuard).has_value());
    }
    EXPECT_EQ(error, PROTOCOL_NEGOTIATION_FAILED);
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, QueryHostBindingStatus_UsesBothUserKeys, TestSize.Level0)
{
    MockGuard guard;
    auto handler = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler, nullptr);
    UserKey companionUser { INT32_200, INVALID_SUB_PROFILE_ID };
    DeviceKey firstHost = hostDeviceKey_;
    DeviceKey secondHost = firstHost;
    secondHost.deviceUserId = INT32_200;
    auto firstBinding = hostBindingStatus_;
    firstBinding.enrolledProtocolId = ProtocolId::VERSION_1;
    auto secondBinding = firstBinding;
    secondBinding.enrolledProtocolId = PROTOCOL_VERSION_2;
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(companionUser, firstHost))
        .WillOnce(Return(std::make_optional(firstBinding)));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(companionUser, secondHost))
        .WillOnce(Return(std::make_optional(secondBinding)));
    auto first = handler->QueryHostBindingStatus(companionUser, firstHost);
    auto second = handler->QueryHostBindingStatus(companionUser, secondHost);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->enrolledProtocolId, ProtocolId::VERSION_1);
    EXPECT_EQ(second->enrolledProtocolId, PROTOCOL_VERSION_2);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
