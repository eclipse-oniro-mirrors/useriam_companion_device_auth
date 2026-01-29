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

#include "host_token_auth_request.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "token_auth_message.h"

#include "adapter_manager.h"
#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class HostTokenAuthRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<HostTokenAuthRequest>(scheduleId_, fwkMsg_, hostUserId_, templateId_,
            std::move(requestCallback_));
    }

protected:
    std::shared_ptr<HostTokenAuthRequest> request_;
    ScheduleId scheduleId_ = 1;
    std::vector<uint8_t> fwkMsg_ = { 1, 2, 3, 4 };
    UserId hostUserId_ = 100;
    TemplateId templateId_ = 12345;
    FwkResultCallback requestCallback_ = [](ResultCode result, const std::vector<uint8_t> &fwkMsg) {};
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    CompanionStatus companionStatus_;
};

HWTEST_F(HostTokenAuthRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_004, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));

    ResultCode errorCode = ResultCode::SUCCESS;
    bool result = true;
    {
        ErrorGuard errorGuard([&errorCode](ResultCode code) { errorCode = code; });
        result = request_->OnStart(errorGuard);
    }

    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, OnConnected_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(HostTokenAuthRequestTest, HostBeginTokenAuth_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HostBeginTokenAuth();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HostBeginTokenAuth_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request_->HostBeginTokenAuth();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    TokenAuthReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    Attributes message;
    EncodeTokenAuthReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    Attributes message;
    request_->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    TokenAuthReply reply = { .result = ResultCode::GENERAL_ERROR, .extraInfo = { 1, 2, 3, 4 } };
    Attributes message;
    EncodeTokenAuthReply(reply, message);

    request_->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_004, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(_))
        .WillByDefault(Return(std::make_optional(companionStatus_)));
    ON_CALL(guard.GetCrossDeviceCommManager(), HostGetSecureProtocolId(_))
        .WillByDefault(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    TokenAuthReply reply = { .result = ResultCode::SUCCESS, .extraInfo = { 1, 2, 3, 4 } };
    Attributes message;
    EncodeTokenAuthReply(reply, message);

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->needEndTokenAuth_ = true;

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithError_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->needEndTokenAuth_ = false;

    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    EXPECT_CALL(guard.GetSecurityAgent(), HostEndTokenAuth(_, _)).Times(0);

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    std::vector<uint8_t> callbackFwkMsg;
    request_->requestCallback_ = [&callbackCalled, &callbackResult, &callbackFwkMsg](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
        callbackFwkMsg = fwkMsg;
    };

    std::vector<uint8_t> testFwkMsg = { 1, 2, 3 };
    request_->CompleteWithSuccess(testFwkMsg);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
    EXPECT_EQ(callbackFwkMsg, testFwkMsg);
}

HWTEST_F(HostTokenAuthRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostTokenAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->callbackInvoked_ = true;

    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    request_->InvokeCallback(ResultCode::SUCCESS, {});

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostTokenAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(HostTokenAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->peerDeviceKey_ = std::nullopt;

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_TOKEN_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostTokenAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::COMPANION_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->peerDeviceKey_ = companionDeviceKey_;

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_TOKEN_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
