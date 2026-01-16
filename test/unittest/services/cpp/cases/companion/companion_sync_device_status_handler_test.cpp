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

#include "companion_sync_device_status_handler.h"
#include "error_guard.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_comm_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_security_agent.h"
#include "mock_user_id_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_200 = 200;
constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_MINUS_1 = -1;

class CompanionSyncDeviceStatusHandlerTest : public Test {
public:
    void SetUp() override
    {
        const int32_t defaultUserId = INT32_100;

        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto activeUserMgr = std::shared_ptr<IUserIdManager>(&mockUserIdManager_, [](IUserIdManager *) {});
        SingletonManager::GetInstance().SetUserIdManager(activeUserMgr);

        auto hostBindingMgr =
            std::shared_ptr<IHostBindingManager>(&mockHostBindingManager_, [](IHostBindingManager *) {});
        SingletonManager::GetInstance().SetHostBindingManager(hostBindingMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        ON_CALL(mockUserIdManager_, GetActiveUserId()).WillByDefault(Return(defaultUserId));
        ON_CALL(mockUserIdManager_, GetActiveUserName()).WillByDefault(Return("TestUser"));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile_));
        ON_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
            .WillByDefault(Return(std::make_optional(hostBindingStatus_)));
        ON_CALL(mockSecurityAgent_, CompanionProcessCheck(_, _)).WillByDefault(Return(ResultCode::SUCCESS));

        handler_ = std::make_unique<CompanionSyncDeviceStatusHandler>();
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    std::unique_ptr<CompanionSyncDeviceStatusHandler> handler_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockUserIdManager> mockUserIdManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;

    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = INT32_100 };
    LocalDeviceProfile profile_ = { .protocols = { ProtocolId::VERSION_1 },
        .companionSecureProtocolId = SecureProtocolId::DEFAULT,
        .capabilities = { Capability::TOKEN_AUTH } };
    DeviceStatus hostDeviceStatus_ = { .deviceKey = hostDeviceKey_,
        .channelId = ChannelId::SOFTBUS,
        .deviceModelInfo = "TestModel",
        .deviceUserName = "TestUser",
        .deviceName = "TestDevice",
        .protocolId = ProtocolId::VERSION_1,
        .secureProtocolId = SecureProtocolId::DEFAULT };
    HostBindingStatus hostBindingStatus_ = { .bindingId = 1,
        .companionUserId = INT32_200,
        .hostDeviceStatus = hostDeviceStatus_ };
};

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_001, TestSize.Level0)
{
    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockUserIdManager_, GetActiveUserId()).WillOnce(Return(INT32_100));
    EXPECT_CALL(mockUserIdManager_, GetActiveUserName()).WillOnce(Return("TestUser"));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile())
        .WillOnce(Return(profile_))
        .WillOnce(Return(profile_));
    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionProcessCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_002, TestSize.Level0)
{
    Attributes request;
    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_003, TestSize.Level0)
{
    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockUserIdManager_, GetActiveUserId()).WillOnce(Return(INT32_MINUS_1));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_004, TestSize.Level0)
{
    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockUserIdManager_, GetActiveUserId()).WillOnce(Return(INT32_100));
    EXPECT_CALL(mockUserIdManager_, GetActiveUserName()).WillOnce(Return("TestUser"));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _)).WillOnce(Return(std::nullopt));

    Attributes reply;
    ErrorGuard errorGuard([](ResultCode) {});
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::SUCCESS));
}

HWTEST_F(CompanionSyncDeviceStatusHandlerTest, HandleRequest_005, TestSize.Level0)
{
    Attributes request;
    SyncDeviceStatusRequest syncDeviceStatusRequest = { .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .hostDeviceKey = hostDeviceKey_,
        .salt = { 1, 2, 3 },
        .challenge = 0 };
    EncodeSyncDeviceStatusRequest(syncDeviceStatusRequest, request);
    request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusRequest.hostDeviceKey.idType));
    request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusRequest.hostDeviceKey.deviceId);

    EXPECT_CALL(mockUserIdManager_, GetActiveUserId()).WillOnce(Return(INT32_100));
    EXPECT_CALL(mockUserIdManager_, GetActiveUserName()).WillOnce(Return("TestUser"));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile())
        .WillOnce(Return(profile_))
        .WillOnce(Return(profile_));
    EXPECT_CALL(mockHostBindingManager_, GetHostBindingStatus(_, _))
        .WillOnce(Return(std::make_optional(hostBindingStatus_)));
    EXPECT_CALL(mockSecurityAgent_, CompanionProcessCheck(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    Attributes reply;
    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });
    handler_->HandleRequest(request, reply);
    int32_t replyResult = 0;

    EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
    EXPECT_EQ(replyResult, static_cast<int32_t>(ResultCode::GENERAL_ERROR));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
