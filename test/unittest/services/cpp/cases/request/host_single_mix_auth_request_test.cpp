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

#include "host_mix_auth_request.h"
#include "host_single_mix_auth_request.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_time_keeper.h"
#include "mock_user_id_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
constexpr int32_t INT32_2 = 2;
namespace {
constexpr int32_t INT32_100 = 100;

class HostSingleMixAuthRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto requestFactory = std::shared_ptr<IRequestFactory>(&mockRequestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto userIdMgr = std::shared_ptr<IUserIdManager>(&mockUserIdManager_, [](IUserIdManager *) {});
        AdapterManager::GetInstance().SetUserIdManager(userIdMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        ON_CALL(mockRequestFactory_, CreateHostTokenAuthRequest(_, _, _, _, _))
            .WillByDefault(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                                      TemplateId templateId, FwkResultCallback &&requestCallback) {
                return std::make_shared<HostTokenAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                    std::move(requestCallback));
            }));
        ON_CALL(mockRequestFactory_, CreateHostDelegateAuthRequest(_, _, _, _, _))
            .WillByDefault(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                                      TemplateId templateId, FwkResultCallback &&requestCallback) {
                return std::make_shared<HostDelegateAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                    std::move(requestCallback));
            }));
        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));
    }

    void TearDown() override
    {
        // Release the request object first, which will cancel all timers
        // Then execute any remaining pending tasks
        request_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

    void CreateDefaultRequest()
    {
        request_ = std::make_shared<HostSingleMixAuthRequest>(scheduleId_, fwkMsg_, hostUserId_, templateId_,
            std::move(requestCallback_));
    }

protected:
    std::shared_ptr<HostSingleMixAuthRequest> request_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserIdManager> mockUserIdManager_;

    ScheduleId scheduleId_ = 1;
    std::vector<uint8_t> fwkMsg_ = { 1, 2, 3, 4 };
    UserId hostUserId_ = INT32_100;
    TemplateId templateId_ = 12345;
    FwkResultCallback requestCallback_ = [](ResultCode result, const std::vector<uint8_t> &fwkMsg) {};
    std::vector<uint8_t> extraInfo_ = { 5, 6, 7, 8 };
};

HWTEST_F(HostSingleMixAuthRequestTest, Start_001, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostTokenAuthRequest(_, _, _, _, _))
        .WillOnce(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                             TemplateId templateId, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostTokenAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                std::move(requestCallback));
        }));
    // HostTokenAuthRequest Start will be called first
    // If it fails, HostDelegateAuthRequest Start may be called, so allow up to 2 Start calls
    EXPECT_CALL(mockRequestManager_, Start(_)).Times(AtMost(INT32_2)).WillRepeatedly(Return(true));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, Start_002, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostTokenAuthRequest(_, _, _, _, _)).WillOnce(Return(nullptr));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, Start_003, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostTokenAuthRequest(_, _, _, _, _))
        .WillOnce(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                             TemplateId templateId, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostTokenAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                std::move(requestCallback));
        }));
    // Allow multiple calls during cleanup - return false for the first call, then true for any additional calls
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false)).WillRepeatedly(Return(true));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_001, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    bool result = request_->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->cancelled_ = true;

    bool result = request_->Cancel(ResultCode::CANCELED);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_003, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    request_->Start();
    bool result = request_->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_004, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    request_->Start();
    request_->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, extraInfo_);
    bool result = request_->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_001, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    request_->Start();
    request_->HandleTokenAuthResult(ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_002, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostDelegateAuthRequest(_, _, _, _, _))
        .WillOnce(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                             TemplateId templateId, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostDelegateAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true)).WillOnce(Return(true));

    request_->Start();
    request_->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_003, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    request_->tokenAuthRequest_ = nullptr;
    request_->HandleTokenAuthResult(ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_004, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostDelegateAuthRequest(_, _, _, _, _)).WillOnce(Return(nullptr));

    request_->Start();
    request_->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_005, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostDelegateAuthRequest(_, _, _, _, _))
        .WillOnce(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                             TemplateId templateId, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostDelegateAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true)).WillOnce(Return(false));

    request_->Start();
    request_->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_001, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    request_->Start();
    request_->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, extraInfo_);
    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_002, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    request_->Start();
    request_->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, extraInfo_);
    request_->HandleDelegateAuthResult(ResultCode::GENERAL_ERROR, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_003, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    request_->delegateAuthRequest_ = nullptr;
    request_->HandleDelegateAuthResult(ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    request_->requestCallback_ = nullptr;
    request_->InvokeCallback(ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 10);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_MIX_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
