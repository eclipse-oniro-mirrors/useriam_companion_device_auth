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

#include "companion_delegate_auth_callback.h"
#include "task_runner_manager.h"
#include "user_auth_client_defines.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionDelegateAuthCallbackTest : public Test {
public:
    void SetUp() override
    {
    }

    void TearDown() override
    {
        callback_.reset();
        TaskRunnerManager::GetInstance().ExecuteAll();
    }

protected:
    std::shared_ptr<CompanionDelegateAuthCallback> callback_;
};

HWTEST_F(CompanionDelegateAuthCallbackTest, OnAcquireInfo_001, TestSize.Level0)
{
    bool callbackCalled = false;
    auto resultCallback = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackCalled = true;
    };

    callback_ = std::make_shared<CompanionDelegateAuthCallback>(std::move(resultCallback));

    UserAuth::Attributes extraInfo;
    callback_->OnAcquireInfo(1, 2, extraInfo);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackCalled);
}

HWTEST_F(CompanionDelegateAuthCallbackTest, OnResult_001, TestSize.Level0)
{
    bool callbackCalled = false;
    ResultCode receivedResult = ResultCode::GENERAL_ERROR;
    std::vector<uint8_t> receivedExtraInfo;

    auto resultCallback = [&callbackCalled, &receivedResult, &receivedExtraInfo](ResultCode result,
                              const std::vector<uint8_t> &extraInfo) {
        callbackCalled = true;
        receivedResult = result;
        receivedExtraInfo = extraInfo;
    };

    callback_ = std::make_shared<CompanionDelegateAuthCallback>(std::move(resultCallback));

    UserAuth::Attributes extraInfo;
    std::vector<uint8_t> testData = { 1, 2, 3, 4 };
    extraInfo.SetUint8ArrayValue(UserAuth::Attributes::ATTR_SIGNATURE, testData);

    callback_->OnResult(static_cast<int32_t>(ResultCode::SUCCESS), extraInfo);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedResult, ResultCode::SUCCESS);
    EXPECT_FALSE(receivedExtraInfo.empty());
}

HWTEST_F(CompanionDelegateAuthCallbackTest, OnResult_002, TestSize.Level0)
{
    bool callbackCalled = false;
    ResultCode receivedResult = ResultCode::SUCCESS;

    auto resultCallback = [&callbackCalled, &receivedResult](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackCalled = true;
        receivedResult = result;
    };

    callback_ = std::make_shared<CompanionDelegateAuthCallback>(std::move(resultCallback));

    UserAuth::Attributes extraInfo;
    callback_->OnResult(static_cast<int32_t>(ResultCode::GENERAL_ERROR), extraInfo);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedResult, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionDelegateAuthCallbackTest, HandleResult_001, TestSize.Level0)
{
    bool callbackCalled = false;
    int32_t receivedResult = -1;
    std::vector<uint8_t> receivedData;

    auto resultCallback = [&callbackCalled, &receivedResult, &receivedData](ResultCode result,
                              const std::vector<uint8_t> &extraInfo) {
        callbackCalled = true;
        receivedResult = static_cast<int32_t>(result);
        receivedData = extraInfo;
    };

    callback_ = std::make_shared<CompanionDelegateAuthCallback>(std::move(resultCallback));

    std::vector<uint8_t> testData = { 5, 6, 7, 8 };
    callback_->HandleResult(static_cast<int32_t>(ResultCode::SUCCESS), testData);

    EXPECT_TRUE(callbackCalled);
    EXPECT_EQ(receivedResult, static_cast<int32_t>(ResultCode::SUCCESS));
    EXPECT_EQ(receivedData, testData);
}

HWTEST_F(CompanionDelegateAuthCallbackTest, HandleResult_002, TestSize.Level0)
{
    bool callbackCalled = false;

    auto resultCallback = [&callbackCalled](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        callbackCalled = true;
    };

    callback_ = std::make_shared<CompanionDelegateAuthCallback>(std::move(resultCallback));

    callback_->HandleResult(static_cast<int32_t>(ResultCode::SUCCESS), {});
    callback_->HandleResult(static_cast<int32_t>(ResultCode::SUCCESS), {});

    EXPECT_TRUE(callbackCalled);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
