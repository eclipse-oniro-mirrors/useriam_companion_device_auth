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

#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_event_manager_adapter.h"
#include "mock_misc_manager.h"
#include "mock_request.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_time_keeper.h"
#include "mock_user_id_manager.h"

#include "adapter_manager.h"
#include "host_sync_device_status_request.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// 测试数据常量
constexpr int32_t HOST_USER_ID = 100;
const DeviceKey COMPANION_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "companion_device_id",
    .deviceUserId = 200 };
const DeviceKey HOST_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "host_device_id",
    .deviceUserId = 100 };
const std::string COMPANION_DEVICE_NAME = "test_companion_name";
const LocalDeviceProfile PROFILE = { .protocols = { ProtocolId::VERSION_1 },
    .capabilities = { Capability::TOKEN_AUTH } };

SyncDeviceStatusReply MakeDefaultSyncDeviceStatusReply()
{
    return {
        .result = ResultCode::SUCCESS,
        .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .secureProtocolId = SecureProtocolId::DEFAULT,
        .companionDeviceKey = COMPANION_DEVICE_KEY,
        .deviceUserName = "test_user_name",
        .companionCheckResponse = { 1, 2, 3 },
    };
}

class HostSyncDeviceStatusRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto companionMgr = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto userIdMgr = std::shared_ptr<IUserIdManager>(&mockUserIdManager_, [](IUserIdManager *) {});
        AdapterManager::GetInstance().SetUserIdManager(userIdMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        auto eventManagerAdapter =
            std::shared_ptr<IEventManagerAdapter>(&mockEventManagerAdapter_, [](IEventManagerAdapter *) {});
        AdapterManager::GetInstance().SetEventManagerAdapter(eventManagerAdapter);

        ON_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostEndCompanionCheck(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(HOST_DEVICE_KEY)));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(PROFILE));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
        ON_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).WillByDefault(Return());
        ON_CALL(mockEventManagerAdapter_, ReportInteractionEvent(_)).WillByDefault(Return());
    }

    void TearDown() override
    {
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockUserIdManager> mockUserIdManager_;
    NiceMock<MockEventManagerAdapter> mockEventManagerAdapter_;
};

HWTEST_F(HostSyncDeviceStatusRequestTest, OnConnected_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(PROFILE));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    ASSERT_NO_THROW(request->OnConnected());
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_001, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::FAIL) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::FAIL));

    request->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_002, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_003, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, SendSyncDeviceStatusRequest_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(HOST_DEVICE_KEY)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(PROFILE));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    std::vector<uint8_t> salt;
    uint64_t challenge = 0;
    bool result = request->SendSyncDeviceStatusRequest(salt, challenge);

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_001, TestSize.Level0)
{
    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    Attributes reply;
    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply.companionDeviceKey.deviceId);

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::SUCCESS));

    request->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_002, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    Attributes reply;
    request->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_003, TestSize.Level0)
{
    auto errorCalled = std::make_shared<bool>(false);
    auto callback = [errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::GENERAL_ERROR) {
            *errorCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));
    request->peerDeviceKey_ = std::nullopt;

    Attributes reply;
    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply.companionDeviceKey.deviceId);

    request->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_004, TestSize.Level0)
{
    auto successCalled = std::make_shared<bool>(false);
    auto callback = [successCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::SUCCESS) {
            *successCalled = true;
        }
    };
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));
    request->SetPeerDeviceKey(COMPANION_DEVICE_KEY);
    request->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    Attributes reply;
    auto syncDeviceStatusReply = MakeDefaultSyncDeviceStatusReply();
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply.companionDeviceKey.deviceId);

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::SUCCESS));

    request->cancelCompanionCheckGuard_ = nullptr;
    request->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(*successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::GENERAL_ERROR };
    bool result = request->EndCompanionCheck(syncDeviceStatusReply);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_002, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS };
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));
    bool result = request->EndCompanionCheck(syncDeviceStatusReply);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_003, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    SyncDeviceStatusReply syncDeviceStatusReply = { .result = ResultCode::SUCCESS,
        .companionCheckResponse = { 1, 2, 3 } };

    CompanionStatus companionStatus;
    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));
    EXPECT_CALL(mockCompanionManager_, SetTemplateInvalid(_, _)).WillOnce(Return());

    bool result = request->EndCompanionCheck(syncDeviceStatusReply);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, CompleteWithError_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));
    ASSERT_NO_THROW(request->CompleteWithError(ResultCode::SUCCESS));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    SyncDeviceStatus syncDeviceStatus;
    syncDeviceStatus.needSync = true;
    ASSERT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_002, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));
    request->callback_ = nullptr;

    SyncDeviceStatus syncDeviceStatus;
    syncDeviceStatus.needSync = true;
    ASSERT_NO_THROW(request->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus));
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    auto weakPtr = request->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    CompanionStatus status;
    status.companionDeviceStatus.deviceKey = request->GetPeerDeviceKey().value();
    std::vector<CompanionStatus> statusList = { status };

    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request->NeedBeginCompanionCheck();

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_002, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    CompanionStatus status;
    status.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.companionDeviceStatus.deviceKey.deviceId = "mismatch-id";
    std::vector<CompanionStatus> statusList = { status };

    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_003, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    std::vector<CompanionStatus> statusList = {};
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_004, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));
    request->peerDeviceKey_ = std::nullopt;

    bool result = request->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    EXPECT_EQ(request->GetMaxConcurrency(), 100);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    auto callback = [](ResultCode, const SyncDeviceStatus &) {};
    auto request = std::make_shared<HostSyncDeviceStatusRequest>(HOST_USER_ID, COMPANION_DEVICE_KEY,
        COMPANION_DEVICE_NAME, std::move(callback));

    auto newRequest = std::make_shared<MockIRequest>(RequestType::HOST_SYNC_DEVICE_STATUS_REQUEST);
    bool result = request->ShouldCancelOnNewRequest(*newRequest, 0);

    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
