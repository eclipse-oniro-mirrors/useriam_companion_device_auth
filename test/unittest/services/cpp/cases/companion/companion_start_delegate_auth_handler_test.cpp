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
#include "companion_delegate_auth_request.h"
#include "companion_start_delegate_auth_handler.h"
#include "delegate_auth_message.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_user_auth_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_200 = 200;
constexpr uint64_t UINT64_12345 = 12345;

class CompanionStartDelegateAuthHandlerTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestFactory = std::shared_ptr<IRequestFactory>(&mockRequestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        // Initialize UserAuthAdapter to prevent crash
        auto userAuthAdapter = std::shared_ptr<IUserAuthAdapter>(&mockUserAuthAdapter_, [](IUserAuthAdapter *) {});
        AdapterManager::GetInstance().SetUserAuthAdapter(userAuthAdapter);

        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));
        ON_CALL(mockUserAuthAdapter_, BeginDelegateAuth(_, _, _, _)).WillByDefault(Return(UINT64_12345));
        ON_CALL(mockUserAuthAdapter_, CancelAuthentication(_)).WillByDefault(Return(ResultCode::SUCCESS));

        handler_ = std::make_unique<CompanionStartDelegateAuthHandler>();
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        AdapterManager::GetInstance().Reset();
        SingletonManager::GetInstance().Reset();
    }

protected:
    std::unique_ptr<CompanionStartDelegateAuthHandler> handler_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserAuthAdapter> mockUserAuthAdapter_;

    std::string connectionName_ = "test_connection";
    int32_t companionUserId_ = INT32_200;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    std::vector<uint8_t> extraInfo_ = { 1, 2, 3, 4 };
};

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_001, TestSize.Level0)
{
    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    Attributes request;
    EXPECT_TRUE(EncodeStartDelegateAuthRequest(startRequest, request));
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(startRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, startRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockRequestFactory_, CreateCompanionDelegateAuthRequest(_, _, _, _))
        .WillOnce(Invoke([](const std::string &connectionName, int32_t companionUserId, const DeviceKey &hostDeviceKey,
                             const std::vector<uint8_t> &startDelegateAuthRequest) {
            return std::make_shared<CompanionDelegateAuthRequest>(connectionName, companionUserId, hostDeviceKey,
                startDelegateAuthRequest);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_EQ(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_002, TestSize.Level0)
{
    Attributes request;

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_003, TestSize.Level0)
{
    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    Attributes request;
    EXPECT_TRUE(EncodeStartDelegateAuthRequest(startRequest, request));
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(startRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, startRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockRequestFactory_, CreateCompanionDelegateAuthRequest(_, _, _, _)).WillOnce(Return(nullptr));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_004, TestSize.Level0)
{
    StartDelegateAuthRequest startRequest = { .hostDeviceKey = hostDeviceKey_,
        .companionUserId = companionUserId_,
        .extraInfo = extraInfo_ };
    Attributes request;
    EXPECT_TRUE(EncodeStartDelegateAuthRequest(startRequest, request));
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(startRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, startRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockRequestFactory_, CreateCompanionDelegateAuthRequest(_, _, _, _))
        .WillOnce(Invoke([](const std::string &connectionName, int32_t companionUserId, const DeviceKey &hostDeviceKey,
                             const std::vector<uint8_t> &startDelegateAuthRequest) {
            return std::make_shared<CompanionDelegateAuthRequest>(connectionName, companionUserId, hostDeviceKey,
                startDelegateAuthRequest);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionStartDelegateAuthHandlerTest, HandleRequest_005, TestSize.Level0)
{
    Attributes request;
    request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName_);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    int32_t result = 0;
    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, result));
    EXPECT_NE(result, static_cast<int32_t>(ResultCode::SUCCESS));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
