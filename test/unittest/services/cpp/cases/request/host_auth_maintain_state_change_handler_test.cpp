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
#include "auth_maintain_state_change_message.h"
#include "error_guard.h"
#include "host_auth_maintain_state_change_handler.h"
#include "mock_time_keeper.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class HostAuthMaintainStateChangeHandlerTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    std::unique_ptr<HostAuthMaintainStateChangeHandler> handler_;
};

HWTEST_F(HostAuthMaintainStateChangeHandlerTest, HandleRequest_001, TestSize.Level0)
{
    bool callbackCalled = false;
    bool receivedState = false;
    auto callback = [&callbackCalled, &receivedState](bool state) {
        callbackCalled = true;
        receivedState = state;
    };

    handler_ = std::make_unique<HostAuthMaintainStateChangeHandler>(std::move(callback));

    AuthMaintainStateChangeRequestMsg requestMsg = { .authMaintainState = true };
    Attributes request;
    EncodeAuthMaintainStateChangeRequest(requestMsg, request);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_TRUE(receivedState);

    auto replyMsgOpt = DecodeAuthMaintainStateChangeReply(reply);
    EXPECT_TRUE(replyMsgOpt.has_value());
    EXPECT_EQ(replyMsgOpt->result, ResultCode::SUCCESS);
}

HWTEST_F(HostAuthMaintainStateChangeHandlerTest, HandleRequest_002, TestSize.Level0)
{
    bool callbackCalled = false;
    bool receivedState = true;
    auto callback = [&callbackCalled, &receivedState](bool state) {
        callbackCalled = true;
        receivedState = state;
    };

    handler_ = std::make_unique<HostAuthMaintainStateChangeHandler>(std::move(callback));

    AuthMaintainStateChangeRequestMsg requestMsg = { .authMaintainState = false };
    Attributes request;
    EncodeAuthMaintainStateChangeRequest(requestMsg, request);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackCalled);
    EXPECT_FALSE(receivedState);

    auto replyMsgOpt = DecodeAuthMaintainStateChangeReply(reply);
    EXPECT_TRUE(replyMsgOpt.has_value());
    EXPECT_EQ(replyMsgOpt->result, ResultCode::SUCCESS);
}

HWTEST_F(HostAuthMaintainStateChangeHandlerTest, HandleRequest_003, TestSize.Level0)
{
    bool callbackCalled = false;
    auto callback = [&callbackCalled](bool) { callbackCalled = true; };

    handler_ = std::make_unique<HostAuthMaintainStateChangeHandler>(std::move(callback));

    Attributes badRequest;
    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(badRequest, reply);

    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackCalled);

    auto replyMsgOpt = DecodeAuthMaintainStateChangeReply(reply);
    EXPECT_TRUE(replyMsgOpt.has_value());
    EXPECT_EQ(replyMsgOpt->result, ResultCode::GENERAL_ERROR);
}

HWTEST_F(HostAuthMaintainStateChangeHandlerTest, HandleRequest_004, TestSize.Level0)
{
    handler_ = std::make_unique<HostAuthMaintainStateChangeHandler>(nullptr);

    AuthMaintainStateChangeRequestMsg requestMsg = { .authMaintainState = true };
    Attributes request;
    EncodeAuthMaintainStateChangeRequest(requestMsg, request);

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);

    TaskRunnerManager::GetInstance().ExecuteAll();

    auto replyMsgOpt = DecodeAuthMaintainStateChangeReply(reply);
    EXPECT_TRUE(replyMsgOpt.has_value());
    EXPECT_EQ(replyMsgOpt->result, ResultCode::SUCCESS);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
