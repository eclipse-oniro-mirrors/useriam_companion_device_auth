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
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

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

        ON_CALL(mockRequestFactory_, CreateHostSingleMixAuthRequest(_, _, _, _, _))
            .WillByDefault(Invoke([this](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                                      TemplateId templateId, FwkResultCallback &&requestCallback) {
                return std::make_shared<HostSingleMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateId,
                    std::move(requestCallback));
            }));
        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));
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
        request_ = std::make_shared<HostMixAuthRequest>(scheduleId_, fwkMsg_, hostUserId_, templateIdList_,
            std::move(requestCallback_));
    }

protected:
    std::shared_ptr<HostMixAuthRequest> request_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockMiscManager> mockMiscManager_;

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
    request_->Cancel();

    TaskRunnerManager::GetInstance().ExecuteAll();
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

HWTEST_F(HostMixAuthRequestTest, InvokeCallback_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->requestCallback_ = nullptr;

    request_->InvokeCallback(ResultCode::SUCCESS, {});
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
