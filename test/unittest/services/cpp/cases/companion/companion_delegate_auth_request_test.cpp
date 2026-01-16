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

#include "adapter_manager.h"
#include "companion_delegate_auth_request.h"
#include "delegate_auth_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_comm_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_user_auth_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint64_t UINT64_12345 = 12345;

class CompanionDelegateAuthRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto hostBindingMgr =
            std::shared_ptr<IHostBindingManager>(&mockHostBindingManager_, [](IHostBindingManager *) {});
        SingletonManager::GetInstance().SetHostBindingManager(hostBindingMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        // Initialize UserAuthAdapter to prevent crash
        auto userAuthAdapter = std::shared_ptr<IUserAuthAdapter>(&mockUserAuthAdapter_, [](IUserAuthAdapter *) {});
        AdapterManager::GetInstance().SetUserAuthAdapter(userAuthAdapter);

        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(companionDeviceKey_)));
        ON_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
            .WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
            .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
        ON_CALL(mockSecurityAgent_, CompanionBeginDelegateAuth(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, CompanionEndDelegateAuth(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
        ON_CALL(mockUserAuthAdapter_, BeginDelegateAuth(_, _, _, _)).WillByDefault(Return(UINT64_12345));
        ON_CALL(mockUserAuthAdapter_, CancelAuthentication(_)).WillByDefault(Return(ResultCode::SUCCESS));
    }

    void TearDown() override
    {
        request_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        AdapterManager::GetInstance().Reset();
        SingletonManager::GetInstance().Reset();
    }

    void CreateDefaultRequest()
    {
        request_ = std::make_shared<CompanionDelegateAuthRequest>(connectionName_, companionUserId_, hostDeviceKey_,
            startDelegateAuthRequest_);
    }

protected:
    std::shared_ptr<CompanionDelegateAuthRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserAuthAdapter> mockUserAuthAdapter_;

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
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_003, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::INVALID));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, OnStart_004, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(companionDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, CompanionGetSecureProtocolId())
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompanionBeginDelegateAuth_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    bool result = request_->CompanionBeginDelegateAuth();

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, SecureAgentBeginDelegateAuth_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionBeginDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    uint64_t challenge = 0;
    Atl atl = 0;
    bool result = request_->SecureAgentBeginDelegateAuth(challenge, atl);

    EXPECT_FALSE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_001, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(mockSecurityAgent_, CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_002, TestSize.Level0)
{
    CreateDefaultRequest();

    std::vector<uint8_t> badExtraInfo = { 1, 2, 3 };

    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, badExtraInfo);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_003, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(mockSecurityAgent_, CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleDelegateAuthResult_004, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes extraInfoAttrs;
    std::vector<uint8_t> authToken = { 1, 2, 3 };
    extraInfoAttrs.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authToken);
    std::vector<uint8_t> extraInfo = extraInfoAttrs.Serialize();

    EXPECT_CALL(mockSecurityAgent_, CompanionEndDelegateAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_001, TestSize.Level0)
{
    CreateDefaultRequest();

    SendDelegateAuthResultReply reply = { .result = ResultCode::SUCCESS };
    Attributes message;
    EXPECT_TRUE(EncodeSendDelegateAuthResultReply(reply, message));

    request_->HandleSendDelegateAuthResultReply(message);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_002, TestSize.Level0)
{
    CreateDefaultRequest();

    SendDelegateAuthResultReply reply = { .result = ResultCode::GENERAL_ERROR };
    Attributes message;
    EXPECT_TRUE(EncodeSendDelegateAuthResultReply(reply, message));

    request_->HandleSendDelegateAuthResultReply(message);
}

HWTEST_F(CompanionDelegateAuthRequestTest, HandleSendDelegateAuthResultReply_003, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes badMessage;

    request_->HandleSendDelegateAuthResultReply(badMessage);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->contextId_ = 12345;

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithError_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->contextId_ = std::nullopt;

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionDelegateAuthRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->CompleteWithSuccess();
}

HWTEST_F(CompanionDelegateAuthRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(CompanionDelegateAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 1);
}

HWTEST_F(CompanionDelegateAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_DELEGATE_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(CompanionDelegateAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
