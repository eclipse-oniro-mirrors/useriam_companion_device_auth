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

#include "host_mix_auth_request.h"
#include "host_single_mix_auth_request.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;
using OHOS::UserIam::UserAuth::AUTH_SCENE_DEFAULT;
using OHOS::UserIam::UserAuth::AUTH_SCENE_WIDGET_AUTH_NO_DISTURB;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr ScheduleId SCHEDULE_ID = 1;
const std::vector<uint8_t> FWK_MSG = { 1, 2, 3, 4 };
constexpr UserId HOST_USER_ID = 100;
constexpr TemplateId TEMPLATE_ID = 12345;
const std::vector<uint8_t> EXTRA_INFO = { 5, 6, 7, 8 };
const int32_t AUTH_INTENTION = 1;
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };

constexpr uint64_t TOKEN_AUTH_REQ_ID = 1;
constexpr uint64_t DELEGATE_AUTH_REQ_ID = 2;

class HostSingleMixAuthRequestTest : public Test {
public:
    void SetUp() override
    {
        guard_ = std::make_unique<MockGuard>();

        ON_CALL(guard_->GetRequestFactory(), CreateHostTokenAuthRequest(_, _))
            .WillByDefault(Return(
                std::make_shared<MockIRequest>(RequestType::HOST_TOKEN_AUTH_REQUEST, TOKEN_AUTH_REQ_ID, SCHEDULE_ID)));
        ON_CALL(guard_->GetRequestFactory(), CreateHostDelegateAuthRequest(_, _))
            .WillByDefault(Return(std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST,
                DELEGATE_AUTH_REQ_ID, SCHEDULE_ID)));
    }

    void TearDown() override
    {
        guard_.reset();
    }

protected:
    std::unique_ptr<MockGuard> guard_;
};

HWTEST_F(HostSingleMixAuthRequestTest, Start_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostTokenAuthRequest(_, _))
        .WillOnce(Return(std::make_shared<MockIRequest>(RequestType::HOST_TOKEN_AUTH_REQUEST, 1, SCHEDULE_ID)));
    // HostTokenAuthRequest Start will be called first
    // If it fails, HostDelegateAuthRequest Start may be called, so allow up to 2 Start calls
    EXPECT_CALL(guard_->GetRequestManager(), Start(_)).Times(AtMost(2)).WillRepeatedly(Return(true));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, Start_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostTokenAuthRequest(_, _)).WillOnce(Return(nullptr));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, Start_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostTokenAuthRequest(_, _))
        .WillOnce(Return(std::make_shared<MockIRequest>(RequestType::HOST_TOKEN_AUTH_REQUEST, 1, SCHEDULE_ID)));
    // Allow multiple calls during cleanup - return false for the first call, then true for any additional calls
    EXPECT_CALL(guard_->GetRequestManager(), Start(_)).WillOnce(Return(false)).WillRepeatedly(Return(true));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

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

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    request->cancelled_ = true;

    bool result = request->Cancel(ResultCode::CANCELED);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    bool result = request->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostSingleMixAuthRequestTest, Cancel_004, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);
    bool result = request->Cancel(ResultCode::CANCELED);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::CANCELED);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostDelegateAuthRequest(_, _))
        .WillOnce(Return(std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, 2, SCHEDULE_ID)));
    EXPECT_CALL(guard_->GetRequestManager(), Start(_)).WillOnce(Return(true)).WillOnce(Return(true));

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_NoRequestIdStillCallbacksSuccess, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->tokenAuthRequestId_.reset();
    request->HandleTokenAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_004, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostDelegateAuthRequest(_, _)).WillOnce(Return(nullptr));

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_005, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostDelegateAuthRequest(_, _))
        .WillOnce(Return(std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, 2, SCHEDULE_ID)));
    EXPECT_CALL(guard_->GetRequestManager(), Start(_)).WillOnce(Return(true)).WillOnce(Return(false));

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_006, TestSize.Level0)
{
    // HandleTokenAuthResult should skip when cancelled_ is true
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    request->cancelled_ = true;
    request->HandleTokenAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_007, TestSize.Level0)
{
    // When TOKEN_AUTH not supported, fallback to DELEGATE_AUTH
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    EXPECT_CALL(guard_->GetCompanionManager(), IsCapabilitySupported(_, Capability::TOKEN_AUTH))
        .WillOnce(Return(false));
    EXPECT_CALL(guard_->GetCompanionManager(), IsCapabilitySupported(_, Capability::DELEGATE_AUTH))
        .WillOnce(Return(true));
    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostDelegateAuthRequest(_, _))
        .WillOnce(Return(std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, 2, SCHEDULE_ID)));
    EXPECT_CALL(guard_->GetRequestManager(), Start(_)).WillOnce(Return(true));

    request->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_NoDisturb_SkipsDelegateAuth, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION,
        AUTH_SCENE_WIDGET_AUTH_NO_DISTURB };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_NoDisturb_SuccessStillCompletesSuccess, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION,
        AUTH_SCENE_WIDGET_AUTH_NO_DISTURB };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_NoDisturb_DoesNotCreateDelegateAuthRequest,
    TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION,
        AUTH_SCENE_WIDGET_AUTH_NO_DISTURB };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostDelegateAuthRequest(_, _)).Times(Exactly(0));

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleTokenAuthResult_DefaultScene_TriesDelegateAuthOnFailure, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    EXPECT_CALL(guard_->GetRequestFactory(), CreateHostDelegateAuthRequest(_, _))
        .WillOnce(Return(std::make_shared<MockIRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, 2, SCHEDULE_ID)));
    EXPECT_CALL(guard_->GetRequestManager(), Start(_)).WillOnce(Return(true)).WillOnce(Return(true));

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);
    request->HandleDelegateAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::SUCCESS);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->Start();
    request->HandleTokenAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);
    request->HandleDelegateAuthResult(ResultCode::GENERAL_ERROR, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    auto callbackResult = std::make_shared<ResultCode>(ResultCode::GENERAL_ERROR);
    request->requestCallback_ = [callbackCalled, callbackResult](ResultCode result, const std::vector<uint8_t> &) {
        *callbackCalled = true;
        *callbackResult = result;
    };

    request->delegateAuthRequestId_.reset();
    request->HandleDelegateAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*callbackCalled);
    EXPECT_EQ(*callbackResult, ResultCode::SUCCESS);
}

HWTEST_F(HostSingleMixAuthRequestTest, HandleDelegateAuthResult_004, TestSize.Level0)
{
    // HandleDelegateAuthResult should skip when cancelled_ is true
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    request->cancelled_ = true;
    request->HandleDelegateAuthResult(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto callbackCalled = std::make_shared<bool>(false);
    request->requestCallback_ = [callbackCalled](ResultCode, const std::vector<uint8_t> &) { *callbackCalled = true; };

    request->requestCallback_ = nullptr;
    request->InvokeCallback(ResultCode::SUCCESS, EXTRA_INFO);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_FALSE(*callbackCalled);
}

HWTEST_F(HostSingleMixAuthRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 10);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_MIX_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_002, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

HWTEST_F(HostSingleMixAuthRequestTest, ShouldCancelOnNewRequest_003, TestSize.Level0)
{
    AuthRequestParams params = { SCHEDULE_ID, FWK_MSG, HOST_USER_ID, TEMPLATE_ID, AUTH_INTENTION, AUTH_SCENE_DEFAULT };
    auto callback = [](ResultCode, const std::vector<uint8_t> &) {};
    auto request = std::make_shared<HostSingleMixAuthRequest>(params, COMPANION_DEVICE_KEY, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_ADD_COMPANION_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
