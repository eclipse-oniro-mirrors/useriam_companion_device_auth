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

#include "mock_guard.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "companion_delegate_auth_request.h"
#include "delegate_auth_message.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionDelegateAuthRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<CompanionDelegateAuthRequest>(connectionName_, companionUserId_, hostDeviceKey_,
            startDelegateAuthRequest_);
    }

protected:
    std::shared_ptr<CompanionDelegateAuthRequest> request_;

    std::string connectionName_ = "test_connection";
    int32_t companionUserId_ = 200;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    std::vector<uint8_t> startDelegateAuthRequest_ = { 1, 2, 3, 4 };
    BindingId bindingId_ = 1;
    HostBindingStatus hostBindingStatus_ = { .bindingId = bindingId_ };
};

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(guard.GetUserAuthAdapter(), BeginDelegateAuth(_, _, _, _)).WillOnce(Return(12345));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompanionBeginDelegateAuth_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    bool result = request_->CompanionBeginDelegateAuth();

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, SecureAgentBeginDelegateAuth_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    uint64_t challenge = 0;
    Atl atl = 0;
    bool result = request_->SecureAgentBeginDelegateAuth(challenge, atl);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &, MessageType, const Attributes &, OnMessageReply callback) {
            SendDelegateAuthResultReply reply = { .result = ResultCode::SUCCESS };
            Attributes message;
            EncodeSendDelegateAuthResultReply(reply, message);
            callback(message);
            return true;
        }));

    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    std::vector<uint8_t> badExtraInfo = { 1, 2, 3 };

    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, badExtraInfo);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_004, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(guard.GetSecurityAgent(), CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    SendDelegateAuthResultReply reply = { .result = ResultCode::SUCCESS };
    Attributes message;
    EncodeSendDelegateAuthResultReply(reply, message);

    request_->HandleSendDelegateAuthResultReply(message);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    SendDelegateAuthResultReply reply = { .result = ResultCode::GENERAL_ERROR };
    Attributes message;
    EncodeSendDelegateAuthResultReply(reply, message);

    request_->HandleSendDelegateAuthResultReply(message);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    Attributes badMessage;

    request_->HandleSendDelegateAuthResultReply(badMessage);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->contextId_ = 12345;

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->contextId_ = std::nullopt;

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    request_->CompleteWithSuccess();
}

HWTEST_F(CompanionDelegateAuthRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(CompanionDelegateAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 1);
}

HWTEST_F(CompanionDelegateAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_DELEGATE_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
