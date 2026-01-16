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
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_companion_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class HostMixAuthRequestTest : public Test {
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

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        ON_CALL(mockRequestFactory_, CreateHostSingleMixAuthRequest(_, _, _, _, _))
            .WillByDefault(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                                      TemplateId templateId, FwkResultCallback &&requestCallback) {
                return std::make_shared<HostSingleMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                    std::move(requestCallback));
            }));
        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));

        // Set up GetCompanionStatus to return a valid companion status for the test templateId
        // Note: In gmock, ON_CALL is evaluated in reverse order (most recent first), so the generic
        // catch-all must be set up before the specific match to ensure proper fallback behavior
        ON_CALL(mockCompanionManager_, GetCompanionStatus(_)).WillByDefault(Return(std::nullopt));
        CompanionStatus companionStatus;
        companionStatus.templateId = templateId_;
        companionStatus.hostUserId = hostUserId_;
        companionStatus.isValid = true;
        ON_CALL(mockCompanionManager_, GetCompanionStatus(templateId_)).WillByDefault(Return(companionStatus));
    }

    void TearDown() override
    {
        // Execute all pending tasks BEFORE releasing the request object
        // to avoid use-after-free crashes
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        request_.reset();
        SingletonManager::GetInstance().Reset();
    }

    void CreateDefaultRequest()
    {
        request_ = std::make_shared<HostMixAuthRequest>(scheduleId_, fwkMsg_, hostUserId_, templateIdList_,
            std::move(requestCallback_));
    }

protected:
    std::shared_ptr<HostMixAuthRequest> request_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;

    ScheduleId scheduleId_ = 1;
    std::vector<uint8_t> fwkMsg_ = { 1, 2, 3, 4 };
    UserId hostUserId_ = 100;
    TemplateId templateId_ = 12345;
    std::vector<TemplateId> templateIdList_ = { templateId_ };
    FwkResultCallback requestCallback_ = [](ResultCode result, const std::vector<uint8_t> &fwkMsg) {};
    std::vector<uint8_t> extraInfo_ = { 5, 6, 7, 8 };
};

HWTEST_F(HostMixAuthRequestTest, Start_001, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostSingleMixAuthRequest(_, _, _, _, _))
        .WillOnce(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                             TemplateId templateId, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostSingleMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, Start_002, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(nullptr));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostMixAuthRequestTest, Start_003, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    EXPECT_CALL(mockRequestFactory_, CreateHostSingleMixAuthRequest(_, _, _, _, _))
        .WillOnce(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                             TemplateId templateId, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostSingleMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, Start_004, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->templateIdList_ = {};
    request_->requestMap_[1] = nullptr;
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::NO_VALID_CREDENTIAL);
}

HWTEST_F(HostMixAuthRequestTest, Cancel_001, TestSize.Level0)
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

HWTEST_F(HostMixAuthRequestTest, Cancel_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->cancelled_ = true;

    bool result = request_->Cancel(ResultCode::CANCELED);

    EXPECT_TRUE(result);
}

HWTEST_F(HostMixAuthRequestTest, Cancel_003, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->requestMap_[1] = nullptr;
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

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_001, TestSize.Level0)
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
    request_->HandleAuthResult(templateId_, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_002, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    request_->Start();
    request_->HandleAuthResult(0, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_003, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    request_->Start();
    request_->requestMap_[templateId_] = nullptr;
    request_->HandleAuthResult(templateId_, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_004, TestSize.Level0)
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
    request_->HandleAuthResult(templateId_, ResultCode::GENERAL_ERROR, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::FAIL);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_005, TestSize.Level0)
{
    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    request_->Start();
    request_->requestMap_.emplace(0, nullptr);
    request_->HandleAuthResult(templateId_, ResultCode::GENERAL_ERROR, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_006, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->templateIdList_ = { templateId_, 99999 };
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    request_->Start();
    request_->HandleAuthResult(templateId_, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_007, TestSize.Level0)
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
    request_->requestMap_[1] = nullptr;
    request_->HandleAuthResult(templateId_, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 1);
}

HWTEST_F(HostMixAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_MIX_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostMixAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostMixAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->requestCallback_ = nullptr;

    EXPECT_NO_THROW(request_->InvokeCallback(ResultCode::SUCCESS, {}));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
