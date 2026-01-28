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

#include "common_message.h"
#include "companion_issue_token_request.h"
#include "companion_pre_issue_token_handler.h"
#include "issue_token_message.h"

#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class CompanionPreIssueTokenHandlerTest : public Test {
protected:
    std::unique_ptr<CompanionPreIssueTokenHandler> handler_;
};

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetRequestFactory(), CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillByDefault(Invoke([this](const std::string &connectionName, const Attributes &request,
                                  OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    ON_CALL(guard.GetRequestManager(), Start(_)).WillByDefault(Return(true));

    handler_ = std::make_unique<CompanionPreIssueTokenHandler>();

    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    DeviceKey hostDeviceKey = {};
    EncodeHostDeviceKey(hostDeviceKey, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 100);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &) { replyCalled = true; };

    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &connectionName, const Attributes &request,
                             OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(true));

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_FALSE(replyCalled);
}

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetRequestFactory(), CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillByDefault(Invoke([this](const std::string &connectionName, const Attributes &request,
                                  OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    ON_CALL(guard.GetRequestManager(), Start(_)).WillByDefault(Return(true));

    handler_ = std::make_unique<CompanionPreIssueTokenHandler>();

    Attributes request;

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetRequestFactory(), CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillByDefault(Invoke([this](const std::string &connectionName, const Attributes &request,
                                  OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    ON_CALL(guard.GetRequestManager(), Start(_)).WillByDefault(Return(true));

    handler_ = std::make_unique<CompanionPreIssueTokenHandler>();

    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_004, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetRequestFactory(), CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillByDefault(Invoke([this](const std::string &connectionName, const Attributes &request,
                                  OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    ON_CALL(guard.GetRequestManager(), Start(_)).WillByDefault(Return(true));

    handler_ = std::make_unique<CompanionPreIssueTokenHandler>();

    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    DeviceKey hostDeviceKey = {};
    EncodeHostDeviceKey(hostDeviceKey, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 100);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionIssueTokenRequest(_, _, _, _)).WillOnce(Return(nullptr));

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

HWTEST_F(CompanionPreIssueTokenHandlerTest, HandleRequest_005, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetRequestFactory(), CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillByDefault(Invoke([this](const std::string &connectionName, const Attributes &request,
                                  OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    ON_CALL(guard.GetRequestManager(), Start(_)).WillByDefault(Return(true));

    handler_ = std::make_unique<CompanionPreIssueTokenHandler>();

    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, "test_connection");
    DeviceKey hostDeviceKey = {};
    EncodeHostDeviceKey(hostDeviceKey, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, 100);

    bool replyCalled = false;
    OnMessageReply onMessageReply = [&replyCalled](const Attributes &reply) {
        replyCalled = true;
        int32_t result = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
        EXPECT_EQ(result, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
    };

    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionIssueTokenRequest(_, _, _, _))
        .WillOnce(Invoke([this](const std::string &connectionName, const Attributes &request,
                             OnMessageReply replyCallback, const DeviceKey &) {
            auto result = DecodePreIssueTokenRequest(request);
            PreIssueTokenRequest preRequest = result.value_or(PreIssueTokenRequest {});
            return std::make_shared<CompanionIssueTokenRequest>(connectionName, request, std::move(replyCallback),
                preRequest.hostDeviceKey);
        }));
    EXPECT_CALL(guard.GetRequestManager(), Start(_)).WillOnce(Return(false));

    handler_->HandleRequest(request, onMessageReply);

    EXPECT_TRUE(replyCalled);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
