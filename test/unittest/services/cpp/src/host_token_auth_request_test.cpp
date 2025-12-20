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
#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "token_auth_message.h"

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

        companionStatus_.companionDeviceStatus.deviceKey = companionDeviceKey_;

        ON_CALL(mockCompanionManager_, GetCompanionStatus(_))
            .WillByDefault(Return(std::make_optional(companionStatus_)));
        ON_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_))
            .WillByDefault(Return(SecureProtocolId::DEFAULT));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillByDefault(Return(true));
        ON_CALL(mockSecurityAgent_, HostBeginTokenAuth(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(hostDeviceKey_)));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
        ON_CALL(mockSecurityAgent_, HostEndTokenAuth(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    }

    void TearDown() override
    {
        request_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

    void CreateDefaultRequest()
    {
        request_ = std::make_shared<HostTokenAuthRequest>(scheduleId_, fwkMsg_, hostUserId_, templateId_,
            std::move(requestCallback_));
    }

protected:
    std::shared_ptr<HostTokenAuthRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;

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
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_)).WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillOnce(Return(true));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_TRUE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_003, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_)).WillOnce(Return(std::nullopt));

    ErrorGuard errorGuard([](ResultCode) {});
    bool result = request_->OnStart(errorGuard);

    EXPECT_FALSE(result);
}

HWTEST_F(HostTokenAuthRequestTest, OnStart_004, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, HostGetSecureProtocolId(_)).WillOnce(Return(SecureProtocolId::DEFAULT));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));

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
    CreateDefaultRequest();

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(mockSecurityAgent_, HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(HostTokenAuthRequestTest, HostBeginTokenAuth_001, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(mockSecurityAgent_, HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HostBeginTokenAuth();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HostBeginTokenAuth_002, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    ErrorGuard errorGuard([](ResultCode) {});
    EXPECT_TRUE(request_->OnStart(errorGuard));

    EXPECT_CALL(mockSecurityAgent_, HostBeginTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    request_->HostBeginTokenAuth();

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_001, TestSize.Level0)
{
    CreateDefaultRequest();
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
    EXPECT_TRUE(EncodeTokenAuthReply(reply, message));

    EXPECT_CALL(mockSecurityAgent_, HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_002, TestSize.Level0)
{
    CreateDefaultRequest();
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
    CreateDefaultRequest();
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
    EXPECT_TRUE(EncodeTokenAuthReply(reply, message));

    request_->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, HandleTokenAuthReply_004, TestSize.Level0)
{
    CreateDefaultRequest();
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
    EXPECT_TRUE(EncodeTokenAuthReply(reply, message));

    EXPECT_CALL(mockSecurityAgent_, HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->HandleTokenAuthReply(message);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithError_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needEndTokenAuth_ = true;

    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(mockSecurityAgent_, HostEndTokenAuth(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithError_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->needEndTokenAuth_ = false;

    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    EXPECT_CALL(mockSecurityAgent_, HostEndTokenAuth(_, _)).Times(0);

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostTokenAuthRequestTest, CompleteWithSuccess_001, TestSize.Level0)
{
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
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostTokenAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
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

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
