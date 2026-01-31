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

#include "host_delegate_auth_request.h"
#include "host_mix_auth_request.h"
#include "host_single_mix_auth_request.h"
#include "host_token_auth_request.h"
#include "service_common.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class HostMixAuthRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<HostMixAuthRequest>(scheduleId_, fwkMsg_, hostUserId_, templateIdList_,
            std::move(requestCallback_));
    }

protected:
    std::shared_ptr<HostMixAuthRequest> request_;
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
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request to return from the factory
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback is not called because request started successfully
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, Start_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Return nullptr to simulate factory failure
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(nullptr));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback should be called with GENERAL_ERROR when factory returns nullptr
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostMixAuthRequestTest, Start_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    // RequestManager::Start returns false
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(false));

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback is not called even though Start failed, because requestMap_ will be empty
    // and Start() will call CompleteWithError(GENERAL_ERROR) at the end
    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, Start_004, TestSize.Level0)
{
    MockGuard guard;

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
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request_->Start();
    bool result = request_->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostMixAuthRequestTest, Cancel_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->cancelled_ = true;

    bool result = request_->Cancel(ResultCode::CANCELED);

    EXPECT_TRUE(result);
}

HWTEST_F(HostMixAuthRequestTest, Cancel_003, TestSize.Level0)
{
    MockGuard guard;

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
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request_->Start();
    request_->HandleAuthResult(templateId_, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request_->Start();
    // TemplateId 0 doesn't exist in requestMap_, so callback should not be called
    request_->HandleAuthResult(0, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_003, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request_->Start();
    // Set request to nullptr, callback should not be called
    request_->requestMap_[templateId_] = nullptr;
    request_->HandleAuthResult(templateId_, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback gets called when request completes successfully
    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_004, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::SUCCESS;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request_->Start();
    // Handle auth result with GENERAL_ERROR, should callback with FAIL since requestMap_ will be empty
    request_->HandleAuthResult(templateId_, ResultCode::GENERAL_ERROR, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::FAIL);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_005, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    request_->requestCallback_ = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request_->Start();
    // Add a nullptr entry with templateId 0, then handle error for templateId_
    // Since requestMap_ won't be empty after erasing templateId_, callback should not be called
    request_->requestMap_.emplace(0, nullptr);
    request_->HandleAuthResult(templateId_, ResultCode::GENERAL_ERROR, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_007, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    bool callbackCalled = false;
    ResultCode callbackResult = ResultCode::GENERAL_ERROR;
    request_->requestCallback_ = [&callbackCalled, &callbackResult](ResultCode result,
                                     const std::vector<uint8_t> &fwkMsg) {
        callbackCalled = true;
        callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(templateId_)).WillOnce(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, scheduleId_);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request_->Start();
    // Add a nullptr entry, then handle SUCCESS for templateId_
    // Should still succeed because the SUCCESS callback should complete the request
    request_->requestMap_[1] = nullptr;
    request_->HandleAuthResult(templateId_, ResultCode::SUCCESS, extraInfo_);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 1);
}

HWTEST_F(HostMixAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_MIX_AUTH_REQUEST, std::nullopt, 0);
    EXPECT_TRUE(result);
}

HWTEST_F(HostMixAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_ADD_COMPANION_REQUEST, std::nullopt, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostMixAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;

    CreateDefaultRequest();
    request_->requestCallback_ = nullptr;

    EXPECT_NO_THROW(request_->InvokeCallback(ResultCode::SUCCESS, {}));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
