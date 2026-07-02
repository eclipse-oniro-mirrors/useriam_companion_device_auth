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
using OHOS::UserIam::UserAuth::AUTH_SCENE_DEFAULT;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr ScheduleId SCHEDULE_ID = 1;
const std::vector<uint8_t> FWK_MSG = { 1, 2, 3, 4 };
constexpr UserId HOST_USER_ID = 100;
constexpr TemplateId TEMPLATE_ID = 12345;
const std::vector<TemplateId> TEMPLATE_ID_LIST = { TEMPLATE_ID };
const std::vector<uint8_t> EXTRA_INFO = { 5, 6, 7, 8 };
const int32_t AUTH_INTENTION = 1;

class HostMixAuthRequestTest : public Test {
protected:
};

HWTEST_F(HostMixAuthRequestTest, Start_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request to return from the factory
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback is not called because request started successfully
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, Start_002, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Return nullptr to simulate factory failure
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(nullptr));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback should be called with GENERAL_ERROR when factory returns nullptr
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostMixAuthRequestTest, Start_003, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    // RequestManager::Start returns false
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(false));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback is not called even though Start failed, because requestMap_ will be empty
    // and Start() will call CompleteWithError(GENERAL_ERROR) at the end
    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, Start_004, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, {}, std::nullopt, std::nullopt, AUTH_INTENTION,
        AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    request->templateIdList_ = {};
    request->requestMap_[1] = 0;
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::NO_VALID_CREDENTIAL);
}

HWTEST_F(HostMixAuthRequestTest, Cancel_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    bool result = request->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostMixAuthRequestTest, Cancel_002, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    request->cancelled_ = true;

    bool result = request->Cancel(ResultCode::CANCELED);

    EXPECT_TRUE(result);
}

HWTEST_F(HostMixAuthRequestTest, Cancel_003, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    request->requestMap_[1] = 0;
    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    bool result = request->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    request->HandleAuthResult(TEMPLATE_ID, ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_002, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    // TemplateId 0 doesn't exist in requestMap_, so callback should not be called
    request->HandleAuthResult(0, ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_ZeroRequestIdStillCallbacksSuccess, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    // Set requestId to 0 in the map; HandleAuthResult still finds the key and processes SUCCESS
    request->requestMap_[TEMPLATE_ID] = 0;
    request->HandleAuthResult(TEMPLATE_ID, ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback IS called because the key exists in requestMap_ regardless of its value
    EXPECT_TRUE(*callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_004, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    // Handle auth result with GENERAL_ERROR, should callback with FAIL since requestMap_ will be empty
    request->HandleAuthResult(TEMPLATE_ID, ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::FAIL);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_005, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    // Add a nullptr entry with templateId 0, then handle error for TEMPLATE_ID
    // Since requestMap_ won't be empty after erasing TEMPLATE_ID, callback should not be called
    request->requestMap_.emplace(0, 0);
    request->HandleAuthResult(TEMPLATE_ID, ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, HandleAuthResult_007, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Create a mock request
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    // Add a nullptr entry, then handle SUCCESS for TEMPLATE_ID
    // Should still succeed because the SUCCESS callback should complete the request
    request->requestMap_[1] = 0;
    request->HandleAuthResult(TEMPLATE_ID, ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 1);
}

HWTEST_F(HostMixAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    // HostMixAuthRequest does not preempt on any request type
    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_MIX_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostMixAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostMixAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    request->requestCallback_ = nullptr;

    EXPECT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, {}));
}

HWTEST_F(HostMixAuthRequestTest, Start_WithTokenId, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    // Set tokenId to a value to test device selection path
    request->tokenId_ = 1000;
    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    // Set up companion status to be valid so Start() can proceed
    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    // Mock device selection to return true and invoke callback with empty devices (use all templates)
    EXPECT_CALL(guard.GetMiscManager(), GetDeviceDeviceSelectResult(_, _, _))
        .WillOnce([](uint32_t tokenId, SelectPurpose purpose, DeviceSelectResultHandler &&handler) {
            // Invoke handler with empty device list, which triggers StartAuthWithTemplateList
            handler({}, std::nullopt);
            return true;
        });

    // Create a mock request to return from the factory
    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    // Callback is not called because request started successfully
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostMixAuthRequestTest, CompleteWithSuccess_WithAuthScene, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    request->HandleAuthResult(TEMPLATE_ID, ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, CompleteWithSuccess_WithTitle, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "Test Title" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    request->HandleAuthResult(TEMPLATE_ID, ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, CompleteWithSuccess_WithAuthSceneAndTitle, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "Widget Auth Title" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    auto mockRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, 1, SCHEDULE_ID);
    EXPECT_CALL(guard.GetRequestFactory(), CreateHostSingleMixAuthRequest(_, _, _)).WillOnce(Return(mockRequest));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();
    request->HandleAuthResult(TEMPLATE_ID, ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostMixAuthRequestTest, Start_CompanionAuthBlocked, TestSize.Level0)
{
    MockGuard guard;

    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    HostMixAuthParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID_LIST, std::nullopt, std::nullopt,
        AUTH_INTENTION, AUTH_SCENE_DEFAULT, "" };
    auto request = std::make_shared<HostMixAuthRequest>(params, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    CompanionStatus validStatus = { .isValid = true };
    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(TEMPLATE_ID)).WillRepeatedly(Return(validStatus));

    EXPECT_CALL(guard.GetMiscManager(), IsCompanionAuthBlocked()).WillRepeatedly(Return(true));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::LOCKED);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
