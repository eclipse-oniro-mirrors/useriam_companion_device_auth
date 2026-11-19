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

#include "binding_signature_message.h"
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
// P-256 DER signature upper bound; enforced by the Rust crypto layer, message layer does not clamp.
constexpr size_t BINDING_SIGNATURE_VALUE_MAX_LEN = 72;
constexpr Capability UNSUPPORTED_CAPABILITY_ID = static_cast<Capability>(999);

class CompanionSyncDeviceStatusHandlerTest : public Test {
protected:
    // Known/unknown protocol+capability mix offer with binding-signature attributes attached.
    void BuildV2IntersectionSyncRequest(Attributes &request)
    {
        const std::vector<ProtocolId> hostProtocolIdList = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 };
        SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = hostProtocolIdList,
            .hostCapabilityList = { Capability::TOKEN_AUTH, UNSUPPORTED_CAPABILITY_ID },
            .hostDeviceKey = hostDeviceKey_,
            .salt = { 1, 2, 3 },
            .challenge = 0 };
        EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
        request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
            static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
        request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);
        request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "sync_connection");
        std::vector<uint8_t> bindingSignatureChallenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
        std::vector<uint8_t> bindingSignatureValue(BINDING_SIGNATURE_VALUE_MAX_LEN, 0xCD);
        AttachBindingSignatureAttributes(bindingSignatureChallenge, bindingSignatureValue, request);
    }

    std::unique_ptr<CompanionSyncDeviceStatusHandler> handler_;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = INT32_100 };
    LocalDeviceProfile profile_ = { .companionProtocols = { ProtocolId::VERSION_1 },
        .companionSecureProtocolId = SecureProtocolId::DEFAULT,
        .companionCapabilities = { Capability::TOKEN_AUTH } };
    DeviceStatus hostDeviceStatus_ = { .deviceKey = hostDeviceKey_,
        .channelId = ChannelId::SOFTBUS,
        .deviceModelInfo = "TestModel",
        .deviceUserName = "TestUser",
        .deviceName = "TestDevice",
        .selectedProtocolId = ProtocolId::VERSION_1,
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    // Decode enforces only the field's presence; consumption is judged in the Rust security
    // layer. The echo is verified with DEFAULT, the only value this build accepts.
    constexpr auto newSecureProtocol = SecureProtocolId::DEFAULT;
    profile.companionSecureProtocolId = newSecureProtocol;
    HostBindingStatus bindingStatus = hostBindingStatus_;

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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

// A host offering only unsupported protocols fails negotiation explicitly; the error reply
// lets the host map it to a retryable failure without invalidating its binding.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_ProtocolNegotiationFailed, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_2 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
// A signed SYNC against a V1 binding is a discovery round: the peer signed a binding it believed
// to be v2, so its view of our enrolled version is wrong. The proof is not consumed, no signature
// check, no collapse — the full advertisement goes back with an empty proof, so the host-side
// empty-proof rule tombstones the drifted credential.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_SignedSyncAgainstV1BindingIsDiscoveryRound,
    TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    LocalDeviceProfile profile = { .companionProtocols = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 },
        .companionSecureProtocolId = SecureProtocolId::DEFAULT,
        .companionCapabilities = { Capability::TOKEN_AUTH } };

    Attributes request;
    BuildV2IntersectionSyncRequest(request);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserTypeName()).WillOnce(Return("normal"));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _)).Times(0);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    auto decoded = DecodeSyncDeviceStatusReply(reply);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->companionProtocolIdList,
        (std::vector<ProtocolId> { ProtocolId::VERSION_1, ProtocolId::VERSION_2 }));
    EXPECT_TRUE(decoded->companionCheckResponse.empty());
    std::vector<uint8_t> proof;
    ASSERT_TRUE(reply.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, proof));
    EXPECT_TRUE(proof.empty());
}

// A signed sync asserting the active user's identity finds no binding for that user: the
// deterministic NOT_ENROLLED refusal goes back with the asserted identity attached, so the
// host settles exactly this credential.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_AssertedActiveUserWithoutBindingReturnsNotEnrolled,
    TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    Attributes request;
    BuildV2IntersectionSyncRequest(request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, INT32_100);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, INVALID_SUB_PROFILE_ID);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _)).Times(0);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::NOT_ENROLLED));
    int32_t replyUserId = 0;
    int32_t replySubProfileId = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, replyUserId));
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, replySubProfileId));
    EXPECT_EQ(replyUserId, INT32_100);
    EXPECT_EQ(replySubProfileId, INVALID_SUB_PROFILE_ID);
}

// A refusal from a bound round (proof verification failed) names the active user too, so the
// host settles exactly this user's credential instead of falling back to the round identity.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_BoundRoundCheckFailureCarriesUserIdentity, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
        .WillOnce(Return(ResultCode::BINDING_SIGNATURE_VERIFY_FAILED));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::BINDING_SIGNATURE_VERIFY_FAILED));
    int32_t replyUserId = 0;
    int32_t replySubProfileId = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, replyUserId));
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, replySubProfileId));
    EXPECT_EQ(replyUserId, INT32_100);
    EXPECT_EQ(replySubProfileId, INVALID_SUB_PROFILE_ID);
}

// The asserted identity names a user that is not the active one: whether or not that user has
// a binding is unknowable here, so the round degrades to discovery with the active user's
// identity and nothing is refused.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_AssertedInactiveUserWithoutBindingStaysDiscovery,
    TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    LocalDeviceProfile profile = { .companionProtocols = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 },
        .companionSecureProtocolId = SecureProtocolId::DEFAULT,
        .companionCapabilities = { Capability::TOKEN_AUTH } };

    Attributes request;
    BuildV2IntersectionSyncRequest(request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, INT32_200);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, INVALID_SUB_PROFILE_ID);

    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { INT32_100, INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetActiveUserName())
        .WillOnce(Return(std::optional<std::string>("TestUser")));
    EXPECT_CALL(guard.GetSystemSettingsManager(), GetSettingsValue(SettingKey::DisplayDeviceName))
        .WillOnce(Return("TestDevice"));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _)).Times(0);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
    int32_t replyUserId = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, replyUserId));
    EXPECT_EQ(replyUserId, INT32_100);
    std::vector<uint8_t> proof;
    ASSERT_TRUE(reply.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, proof));
    EXPECT_TRUE(proof.empty());
}

// An unsigned SYNC against a lingering V2 binding is a discovery round: no signature check, no
// collapse, no SK-encrypted reply — the full advertisement goes back with an empty proof, so the
// host can re-pair over the residual binding (rule 1).
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_UnsignedSyncAgainstV2BindingIsDiscoveryRound,
    TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    LocalDeviceProfile profile = { .companionProtocols = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 },
        .companionSecureProtocolId = SecureProtocolId::DEFAULT,
        .companionCapabilities = { Capability::TOKEN_AUTH } };
    HostBindingStatus v2Binding = hostBindingStatus_;
    v2Binding.enrolledProtocolId = ProtocolId::VERSION_2;

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1,
                                                            ProtocolId::VERSION_2 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
        .WillOnce(Return(std::make_optional(v2Binding)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionProcessCheck(_, _)).Times(0);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    auto decoded = DecodeSyncDeviceStatusReply(reply);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->companionProtocolIdList,
        (std::vector<ProtocolId> { ProtocolId::VERSION_1, ProtocolId::VERSION_2 }));
    EXPECT_TRUE(decoded->companionCheckResponse.empty());
    std::vector<uint8_t> proof;
    ASSERT_TRUE(reply.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, proof));
    EXPECT_TRUE(proof.empty());
}

// An unsigned SYNC against a V1 binding stays on the legacy path: the V1 SK proof is produced
// without a binding signature while the reply keeps the full support set (cards 3/13).
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_UnsignedSyncAgainstV1BindingProvesWithoutSignature,
    TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler_, nullptr);

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1,
                                                            ProtocolId::VERSION_2 },
        .hostCapabilityList = { Capability::TOKEN_AUTH },
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
    EXPECT_EQ(capturedInput.companionProtocolList,
        std::vector<uint16_t> { static_cast<uint16_t>(ProtocolId::VERSION_1) });
    EXPECT_TRUE(capturedInput.bindingSignatureProof.challenge.empty());
    EXPECT_TRUE(capturedInput.bindingSignatureProof.signature.empty());
    std::vector<uint8_t> proof;
    ASSERT_TRUE(reply.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_EXTRA_INFO, proof));
    EXPECT_FALSE(proof.empty());
}

// A bound round announces the complete local support set even when a higher common version
// exists: the companion never narrows the reply by the enrolled version or by the offer; the
// inner proof list is the same complete set as the plaintext outer list.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_BoundRoundRepliesFullSupportSet, TestSize.Level0)
{
    MockGuard guard;

    handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();

    LocalDeviceProfile profile = { .companionProtocols = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 },
        .companionSecureProtocolId = SecureProtocolId::DEFAULT,
        .companionCapabilities = { Capability::TOKEN_AUTH } };
    HostBindingStatus hostBindingStatus = hostBindingStatus_;
    hostBindingStatus.enrolledProtocolId = ProtocolId::VERSION_1;

    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .hostProtocolIdList = { ProtocolId::VERSION_1,
                                                            ProtocolId::VERSION_2 },
        .hostCapabilityList = { Capability::TOKEN_AUTH, UNSUPPORTED_CAPABILITY_ID },
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
    EXPECT_EQ(capturedInput.companionProtocolList,
        (std::vector<uint16_t> { static_cast<uint16_t>(ProtocolId::VERSION_1),
            static_cast<uint16_t>(ProtocolId::VERSION_2) }));

    // The identifier attributes are injected by the transport layer, not by the message encoder;
    // add them before decoding, mirroring what the receiving side sees on the wire.
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
    auto decodedReply = DecodeSyncDeviceStatusReply(reply);
    EXPECT_TRUE(decodedReply.has_value());
    EXPECT_EQ(decodedReply->companionProtocolIdList,
        (std::vector<ProtocolId> { ProtocolId::VERSION_1, ProtocolId::VERSION_2 }));
    EXPECT_EQ(decodedReply->companionCapabilityList, std::vector<Capability> { Capability::TOKEN_AUTH });
    EXPECT_EQ(capturedInput.companionCapabilityList,
        std::vector<uint16_t> { static_cast<uint16_t>(Capability::TOKEN_AUTH) });
}

// The gate is the offer ∩ support intersection; any enrolled version covered by it passes, and the
// binding row must not change the outcome — reply and proof always carry the full support set.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, NegotiateSyncParameters_SucceedsForAnyEnrolledWithinIntersection,
    TestSize.Level0)
{
    auto handler = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler, nullptr);
    LocalDeviceProfile profile = profile_;
    profile.companionProtocols = { ProtocolId::VERSION_2, ProtocolId::VERSION_1 };
    SyncDeviceStatusRequest request;
    request.hostProtocolIdList = profile.companionProtocols;
    request.hostCapabilityList = profile.companionCapabilities;
    ErrorGuard errorGuard([](ResultCode) {});
    for (auto enrolled : profile.companionProtocols) {
        auto binding = hostBindingStatus_;
        binding.enrolledProtocolId = enrolled;
        EXPECT_EQ(handler->NegotiateSyncParameters(request, profile, binding, errorGuard), ResultCode::SUCCESS);
    }
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, NegotiateSyncParameters_DoesNotReplaceUnavailableEnrollment,
    TestSize.Level0)
{
    auto handler = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler, nullptr);
    auto binding = hostBindingStatus_;
    binding.enrolledProtocolId = ProtocolId::VERSION_2;
    LocalDeviceProfile profile = profile_;
    profile.companionProtocols = { ProtocolId::VERSION_1, ProtocolId::VERSION_2 };
    SyncDeviceStatusRequest request;
    request.hostProtocolIdList = { ProtocolId::VERSION_1 };
    request.hostCapabilityList = profile.companionCapabilities;
    ResultCode error = GENERAL_ERROR;
    {
        ErrorGuard errorGuard([&error](ResultCode code) { error = code; });
        EXPECT_EQ(handler->NegotiateSyncParameters(request, profile, binding, errorGuard), PROTOCOL_NEGOTIATION_FAILED);
    }
    EXPECT_EQ(error, PROTOCOL_NEGOTIATION_FAILED);
    request.hostProtocolIdList = profile.companionProtocols;
    {
        ErrorGuard errorGuard([&error](ResultCode code) { error = code; });
        EXPECT_EQ(handler->NegotiateSyncParameters(request, profile_, binding, errorGuard),
            PROTOCOL_NEGOTIATION_FAILED);
    }
    EXPECT_EQ(error, PROTOCOL_NEGOTIATION_FAILED);
}

// The enroll path always persists a real protocol, so INVALID marks a corrupted binding row
// and must be rejected against any offer instead of re-negotiating from the announcement.
HWTEST_F(CompanionSyncDeviceStatusHandlerTest, NegotiateSyncParameters_RejectsBindingWithoutEnrolledProtocol,
    TestSize.Level0)
{
    auto handler = std::make_unique<CompanionSyncDeviceStatusHandler>();
    ASSERT_NE(handler, nullptr);
    auto binding = hostBindingStatus_;
    binding.enrolledProtocolId = ProtocolId::INVALID;
    SyncDeviceStatusRequest request;
    request.hostProtocolIdList = profile_.companionProtocols;
    request.hostCapabilityList = profile_.companionCapabilities;
    ResultCode error = GENERAL_ERROR;
    {
        ErrorGuard errorGuard([&error](ResultCode code) { error = code; });
        EXPECT_EQ(handler->NegotiateSyncParameters(request, profile_, binding, errorGuard),
            PROTOCOL_NEGOTIATION_FAILED);
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
    secondBinding.enrolledProtocolId = ProtocolId::VERSION_2;
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(companionUser, firstHost))
        .WillOnce(Return(std::make_optional(firstBinding)));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(companionUser, secondHost))
        .WillOnce(Return(std::make_optional(secondBinding)));
    auto first = handler->QueryHostBindingStatus(companionUser, firstHost);
    auto second = handler->QueryHostBindingStatus(companionUser, secondHost);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->enrolledProtocolId, ProtocolId::VERSION_1);
    EXPECT_EQ(second->enrolledProtocolId, ProtocolId::VERSION_2);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
