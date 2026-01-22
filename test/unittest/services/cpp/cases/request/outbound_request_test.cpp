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

#include "outbound_request.h"
#include "request_aborted_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_time_keeper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class MockOutboundRequest : public OutboundRequest {
public:
    MockOutboundRequest(RequestType requestType, ScheduleId scheduleId, uint32_t timeoutMs)
        : OutboundRequest(requestType, scheduleId, timeoutMs)
    {
    }

    MOCK_METHOD(void, OnConnected, (), (override));
    MOCK_METHOD(std::weak_ptr<OutboundRequest>, GetWeakPtr, (), (override));
    MOCK_METHOD(void, CompleteWithError, (ResultCode result), (override));
    MOCK_METHOD(uint32_t, GetMaxConcurrency, (), (const, override));
    MOCK_METHOD(bool, ShouldCancelOnNewRequest,
        (RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice, uint32_t subsequentSameTypeCount),
        (const, override));
};

class OutboundRequestTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);
        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        ON_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, _, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillByDefault(Return(true));
        ON_CALL(mockCrossDeviceCommManager_, CloseConnection(_)).WillByDefault(Return());
    }

    void TearDown() override
    {
        request_.reset();
        RelativeTimer::GetInstance().ExecuteAll();
        TaskRunnerManager::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

    void CreateDefaultRequest()
    {
        request_ =
            std::make_shared<MockOutboundRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, scheduleId_, timeoutMs_);
        request_->SetPeerDeviceKey(peerDeviceKey_);
        // Set default behaviors for mock methods that are called internally
        ON_CALL(*request_, GetWeakPtr()).WillByDefault(Return(std::weak_ptr<OutboundRequest>(request_)));
        ON_CALL(*request_, CompleteWithError(_)).WillByDefault(Return());
        ON_CALL(*request_, OnConnected()).WillByDefault(Return());
    }

protected:
    std::shared_ptr<MockOutboundRequest> request_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockMiscManager> mockMiscManager_;

    ScheduleId scheduleId_ = 1;
    uint32_t timeoutMs_ = 30000;
    DeviceKey peerDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "peer_device_id",
        .deviceUserId = 200 };
};

HWTEST_F(OutboundRequestTest, Start_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillOnce(Return(true));

    request_->Start();
}

HWTEST_F(OutboundRequestTest, Start_002, TestSize.Level0)
{
    request_ = std::make_shared<MockOutboundRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, scheduleId_, timeoutMs_);

    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(OutboundRequestTest, OnStart_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));

    ResultCode errorCode = ResultCode::SUCCESS;
    bool result = false;
    {
        ErrorGuard errorGuard([&errorCode](ResultCode code) { errorCode = code; });
        result = request_->OnStart(errorGuard);
    }

    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(OutboundRequestTest, OnStart_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(nullptr));

    ResultCode errorCode = ResultCode::SUCCESS;
    bool result = false;
    {
        ErrorGuard errorGuard([&errorCode](ResultCode code) { errorCode = code; });
        result = request_->OnStart(errorGuard);
    }

    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(OutboundRequestTest, OnStart_003, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(mockCrossDeviceCommManager_, OpenConnection(_, _)).WillOnce(Return(false));

    ResultCode errorCode = ResultCode::SUCCESS;
    bool result = false;
    {
        ErrorGuard errorGuard([&errorCode](ResultCode code) { errorCode = code; });
        result = request_->OnStart(errorGuard);
    }

    EXPECT_FALSE(result);
    EXPECT_EQ(errorCode, ResultCode::COMMUNICATION_ERROR);
}

HWTEST_F(OutboundRequestTest, Cancel_001, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    bool result = request_->Cancel(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
}

HWTEST_F(OutboundRequestTest, Cancel_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->cancelled_ = true;

    bool result = request_->Cancel(ResultCode::GENERAL_ERROR);

    EXPECT_TRUE(result);
}

HWTEST_F(OutboundRequestTest, SetPeerDeviceKey_001, TestSize.Level0)
{
    request_ = std::make_shared<MockOutboundRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, scheduleId_, timeoutMs_);

    request_->SetPeerDeviceKey(peerDeviceKey_);

    std::optional<DeviceKey> deviceKey = request_->GetPeerDeviceKey();
    EXPECT_TRUE(deviceKey.has_value());
    EXPECT_EQ(deviceKey->deviceId, peerDeviceKey_.deviceId);
}

HWTEST_F(OutboundRequestTest, CloseConnection_001, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->connectionName_ = "test_connection";

    EXPECT_CALL(mockCrossDeviceCommManager_, CloseConnection(_)).WillOnce(Return());

    request_->CloseConnection();

    EXPECT_TRUE(request_->GetConnectionName().empty());
}

HWTEST_F(OutboundRequestTest, CloseConnection_002, TestSize.Level0)
{
    CreateDefaultRequest();
    request_->connectionName_ = "";

    EXPECT_CALL(mockCrossDeviceCommManager_, CloseConnection(_)).Times(0);

    request_->CloseConnection();
}

HWTEST_F(OutboundRequestTest, HandleConnectionStatus_001, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->HandleConnectionStatus("test_connection", ConnectionStatus::ESTABLISHING, "establishing");
}

HWTEST_F(OutboundRequestTest, HandleConnectionStatus_002, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(*request_, OnConnected()).WillOnce(Return());

    request_->HandleConnectionStatus("test_connection", ConnectionStatus::CONNECTED, "connected");
}

HWTEST_F(OutboundRequestTest, HandleConnectionStatus_003, TestSize.Level0)
{
    CreateDefaultRequest();

    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    request_->HandleConnectionStatus("test_connection", ConnectionStatus::DISCONNECTED, "disconnected");
}

HWTEST_F(OutboundRequestTest, HandleConnectionStatus_004, TestSize.Level0)
{
    CreateDefaultRequest();

    request_->HandleConnectionStatus("test_connection", static_cast<ConnectionStatus>(999), "unknown");

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(OutboundRequestTest, HandleRequestAborted_001, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes request;
    RequestAbortedRequest abortReq;
    abortReq.result = ResultCode::TIMEOUT;
    abortReq.reason = "test_reason";
    EXPECT_TRUE(EncodeRequestAbortedRequest(abortReq, request));

    bool replyCalled = false;
    OnMessageReply onReply = [&replyCalled](const Attributes &reply) { replyCalled = true; };

    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return()).WillOnce(Return());

    request_->HandleRequestAborted(request, onReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(OutboundRequestTest, HandleRequestAborted_002, TestSize.Level0)
{
    CreateDefaultRequest();

    Attributes request;

    bool replyCalled = false;
    OnMessageReply onReply = [&replyCalled](const Attributes &reply) { replyCalled = true; };

    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    request_->HandleRequestAborted(request, onReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
