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

#include "adapter_manager.h"
#include "mock_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class HostSyncDeviceStatusRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
            std::move(syncDeviceStatusCallback_));
    }

protected:
    std::shared_ptr<HostSyncDeviceStatusRequest> request_;

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
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(true));

    request_->OnConnected();
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_001, TestSize.Level0)
{
    MockGuard guard;
    bool errorCalled = false;
    syncDeviceStatusCallback_ = [&errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::FAIL) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::FAIL));

    request_->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_002, TestSize.Level0)
{
    MockGuard guard;
    bool errorCalled = false;
    syncDeviceStatusCallback_ = [&errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));

    request_->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, BeginCompanionCheck_003, TestSize.Level0)
{
    MockGuard guard;
    bool errorCalled = false;
    syncDeviceStatusCallback_ = [&errorCalled](ResultCode result, const SyncDeviceStatus &) {
        if (result == ResultCode::COMMUNICATION_ERROR) {
            errorCalled = true;
        }
    };

    request_ = std::make_shared<HostSyncDeviceStatusRequest>(hostUserId_, companionDeviceKey_, companionDeviceName_,
        std::move(syncDeviceStatusCallback_));

    EXPECT_CALL(guard.GetSecurityAgent(), HostBeginCompanionCheck(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_)).WillOnce(Return(std::nullopt));
    EXPECT_CALL(guard.GetSecurityAgent(), HostCancelCompanionCheck(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    request_->BeginCompanionCheck();

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(errorCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, SendSyncDeviceStatusRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceKeyByConnectionName(_))
        .WillOnce(Return(std::make_optional(hostDeviceKey_)));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetLocalDeviceProfile()).WillOnce(Return(profile_));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillOnce(Return(false));

    std::vector<uint8_t> salt;
    uint64_t challenge = 0;
    bool result = request_->SendSyncDeviceStatusRequest(salt, challenge);

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_001, TestSize.Level0)
{
    MockGuard guard;
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

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCompanionManager(), UpdateCompanionStatus(_, _, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, HandleSyncDeviceStatusReply_002, TestSize.Level0)
{
    MockGuard guard;
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
    MockGuard guard;
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
    MockGuard guard;
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

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(guard.GetCompanionManager(), UpdateCompanionStatus(_, _, _)).WillOnce(Return(ResultCode::SUCCESS));

    request_->cancelCompanionCheckGuard_ = nullptr;
    request_->HandleSyncDeviceStatusReply(reply);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(successCalled);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    SyncDeviceStatusReply syncDeviceStatusReply_ = { .result = ResultCode::GENERAL_ERROR };

    bool result = request_->EndCompanionCheck(syncDeviceStatusReply_);

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    SyncDeviceStatusReply syncDeviceStatusReply_ = { .result = ResultCode::SUCCESS };

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _)).WillOnce(Return(std::nullopt));
    bool result = request_->EndCompanionCheck(syncDeviceStatusReply_);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, EndCompanionCheck_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    SyncDeviceStatusReply syncDeviceStatusReply_ = { .result = ResultCode::SUCCESS };

    EXPECT_CALL(guard.GetCompanionManager(), GetCompanionStatus(_, _))
        .WillOnce(Return(std::make_optional(companionStatus_)));
    EXPECT_CALL(guard.GetSecurityAgent(), HostEndCompanionCheck(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));
    EXPECT_CALL(guard.GetCompanionManager(), HandleCompanionCheckFail(_)).WillOnce(Return(ResultCode::SUCCESS));

    bool result = request_->EndCompanionCheck(syncDeviceStatusReply_);

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->CompleteWithError(ResultCode::SUCCESS);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->callbackInvoked_ = true;
    SyncDeviceStatus syncDeviceStatus;
    request_->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, InvokeCallback_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();
    request_->callback_ = nullptr;
    SyncDeviceStatus syncDeviceStatus;
    request_->InvokeCallback(ResultCode::SUCCESS, syncDeviceStatus);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetWeakPtr_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    auto weakPtr = request_->GetWeakPtr();
    EXPECT_FALSE(weakPtr.expired());
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    CompanionStatus status;
    status.companionDeviceStatus.deviceKey = request_->peerDeviceKey_.value();
    std::vector<CompanionStatus> statusList = { status };

    EXPECT_CALL(guard.GetCompanionManager(), GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request_->NeedBeginCompanionCheck();

    EXPECT_TRUE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_002, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    CompanionStatus status;
    status.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.companionDeviceStatus.deviceKey.deviceId = "mismatch-id";
    std::vector<CompanionStatus> statusList = { status };

    EXPECT_CALL(guard.GetCompanionManager(), GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request_->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_003, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    std::vector<CompanionStatus> statusList = {};
    EXPECT_CALL(guard.GetCompanionManager(), GetAllCompanionStatus()).WillOnce(Return(statusList));

    bool result = request_->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, NeedBeginCompanionCheck_004, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    request_->peerDeviceKey_ = std::nullopt;
    bool result = request_->NeedBeginCompanionCheck();

    EXPECT_FALSE(result);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, GetMaxConcurrency_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    EXPECT_EQ(request_->GetMaxConcurrency(), 100);
}

HWTEST_F(HostSyncDeviceStatusRequestTest, ShouldCancelOnNewRequest_001, TestSize.Level0)
{
    MockGuard guard;
    CreateDefaultRequest();

    bool result = request_->ShouldCancelOnNewRequest(RequestType::HOST_SYNC_DEVICE_STATUS_REQUEST, std::nullopt, 0);

    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS