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

#include "host_sync_device_status_request.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

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

        ON_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostEndCompanionCheck(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
            .WillByDefault(Return(std::make_optional(hostDeviceKey_)));
        ON_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillByDefault(Return(profile_));
        ON_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillByDefault(Return(true));
        ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _))
            .WillByDefault(Return(std::make_optional(companionStatus_)));
        ON_CALL(mockCompanionManager_, UpdateCompanionStatus(_, _, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockCompanionManager_, HandleCompanionCheckFail(_)).WillByDefault(Return(ResultCode::SUCCESS));
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
        request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
            std::move(syncDeviceStatusCallback_));
    }

protected:
    std::shared_ptr<HostSyncDeviceStatusRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;

    int32_t hostUserId_ = 100;
    DeviceKey companionDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "companion_device_id",
        .deviceUserId = 200 };
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    std::string companionDeviceName_ = "test_companion_name";
    SyncDeviceStatusCallback syncDeviceStatusCallback_ = [](ResultCode, const SyncDeviceStatus &) {};
    LocalDeviceProfile profile_ = { .protocols = { ProtocolId::VERSION_1 },
        .capabilities = { Capability::TOKEN_AUTH } };
    CompanionStatus companionStatus_;
};

HWTEST_F(HostSyncDeviceStatusRequestTest, OnConnected_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_001, TestSize.Level0)
{
    bool errorCalled = false;
    syncDeviceStatusCallback_ = [&errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::FAIL) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::FAIL));

    request_->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_002, TestSize.Level0)
{
    bool errorCalled = false;
    syncDeviceStatusCallback_ = [&errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request_->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_003, TestSize.Level0)
{
    bool errorCalled = false;
    syncDeviceStatusCallback_ = [&errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));

    EXPECT_CALL(mockSecurityAgent_, HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(mockSecurityAgent_, HostCancelCompanionCheck(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, SendSyncDeviceStatusRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(mockCrossDeviceCommManager_, SendMessage(_, _, _, _)).WillOnce(Return(false));

    std::vector<uint8_t> salt;
    uint64_t challenge = 0;
    bool result = request_->SendSyncDeviceStatusRequest(salt, challenge);

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_001, TestSize.Level0)
{
    bool successCalled = false;
    syncDeviceStatusCallback_ = [&successCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::SUCCESS) {
            successCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);
    request_->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    Attributes reply;
    SyncDeviceStatusReply syncDeviceStatusReply_ = {
        .result = ResultCode::SUCCESS,
        .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .secureProtocolId = SecureProtocolId::DEFAULT,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = "test_user_name",
        .companionCheckResponse = { 1, 2, 3 },
    };
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply_, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply_.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply_.companionDeviceKey.deviceId);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCompanionManager_, UpdateCompanionStatus(_, _, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_002, TestSize.Level0)
{
    bool errorCalled = false;
    syncDeviceStatusCallback_ = [&errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));

    Attributes reply;
    request_->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_003, TestSize.Level0)
{
    bool errorCalled = false;
    syncDeviceStatusCallback_ = [&errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::GENERAL_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));
    request_->peerDeviceKey_ = std::nullopt;

    Attributes reply;
    SyncDeviceStatusReply syncDeviceStatusReply_ = {
        .result = ResultCode::SUCCESS,
        .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .secureProtocolId = SecureProtocolId::DEFAULT,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = "test_user_name",
        .companionCheckResponse = { 1, 2, 3 },
    };
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply_, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply_.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply_.companionDeviceKey.deviceId);

    request_->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_004, TestSize.Level0)
{
    bool successCalled = false;
    syncDeviceStatusCallback_ = [&successCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::SUCCESS) {
            successCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));
    request_->SetPeerDeviceKey(companionDeviceKey_);
    request_->cancelCompanionCheckGuard_ = std::make_unique<ScopeGuard>([]() {});

    Attributes reply;
    SyncDeviceStatusReply syncDeviceStatusReply_ = {
        .result = ResultCode::SUCCESS,
        .protocolIdList = { ProtocolId::VERSION_1 },
        .capabilityList = { Capability::TOKEN_AUTH },
        .secureProtocolId = SecureProtocolId::DEFAULT,
        .companionDeviceKey = companionDeviceKey_,
        .deviceUserName = "test_user_name",
        .companionCheckResponse = { 1, 2, 3 },
    };
    EncodeSyncDeviceStatusReply(syncDeviceStatusReply_, reply);
    reply.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE,
        static_cast<int32_t>(syncDeviceStatusReply_.companionDeviceKey.idType));
    reply.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, syncDeviceStatusReply_.companionDeviceKey.deviceId);

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCompanionManager_, UpdateCompanionStatus(_, _, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->cancelCompanionCheckGuard_ = nullptr;
    request_->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_001, TestSize.Level0)
{
    CreateDefaultRequest();
    SyncDeviceStatusReply syncDeviceStatusReply_ = { .result = ResultCode::GENERAL_ERROR };

    bool result = request_->EndCompanionCheck(syncDeviceStatusReply_);

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_002, TestSize.Level0)
{
    CreateDefaultRequest();
    SyncDeviceStatusReply syncDeviceStatusReply_ = { .result = ResultCode::SUCCESS };

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));
    bool result = request_->EndCompanionCheck(syncDeviceStatusReply_);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_003, TestSize.Level0)
{
    CreateDefaultRequest();
    SyncDeviceStatusReply syncDeviceStatusReply_ = { .result = ResultCode::SUCCESS };

    EXPECT_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(mockSecurityAgent_, HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));
    EXPECT_CALL(mockCompanionManager_, HandleCompanionCheckFail(_)).WillOnce(Return(ResultCode::SUCCESS));

    bool result = request_->EndCompanionCheck(syncDeviceStatusReply_);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, CompleteWithError_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->CompleteWithError(ResultCode::SUCCESS);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->callbackInvoked_ = true;
    SyncDeviceStatus syncDeviceStatus;
    request_->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->callback_ = nullptr;
    SyncDeviceStatus syncDeviceStatus;
    request_->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_001, TestSize.Level0)
{
    CreateDefaultRequest();

    CompanionStatus status;
    status.companionDeviceStatus.deviceKey = request_->peerDeviceKey_.value();
    std::vector<CompanionStatus> statusList = { status };

    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request_->NeedBeginCompanionCheck();

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_002, TestSize.Level0)
{
    CreateDefaultRequest();

    CompanionStatus status;
    status.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.companionDeviceStatus.deviceKey.deviceId = "mismatch-id";
    std::vector<CompanionStatus> statusList = { status };

    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request_->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_003, TestSize.Level0)
{
    CreateDefaultRequest();

    std::vector<CompanionStatus> statusList = {};
    EXPECT_CALL(mockCompanionManager_, GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request_->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_004, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->peerDeviceKey_ = std::nullopt;
    bool result = request_->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 100);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_SYNC_DEVICE_STATUS_REQUEST, std::nullopt, 0);

    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS