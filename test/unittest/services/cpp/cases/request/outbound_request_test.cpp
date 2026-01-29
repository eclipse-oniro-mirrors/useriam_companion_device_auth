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
#include <memory>

#include "outbound_request.h"
#include "request_aborted_message.h"
#include "task_runner_manager.h"

#include "mock_guard.h"

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

// Test implementation that only mocks what's necessary, avoiding CFI issues
class MockOutboundRequest : public OutboundRequest, public std::enable_shared_from_this<MockOutboundRequest> {
public:
    MockOutboundRequest(RequestType requestType, ScheduleId scheduleId, uint32_t timeoutMs)
        : OutboundRequest(requestType, scheduleId, timeoutMs)
    {
    }

    MOCK_METHOD(void, OnConnected, (), (override));

    // Return real weak_ptr to this object - don't mock to avoid CFI issues
    std::weak_ptr<OutboundRequest> GetWeakPtr() override
    {
        return shared_from_this();
    }

    // Implement pure virtual methods with mock implementations
    MOCK_METHOD(void, CompleteWithError, (ResultCode result), (override));
    MOCK_METHOD(uint32_t, GetMaxConcurrency, (), (const, override));
    MOCK_METHOD(bool, ShouldCancelOnNewRequest,
        (RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice, uint32_t subsequentSameTypeCount),
        (const, override));
};

class OutboundRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ =
            std::make_shared<MockOutboundRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, scheduleId_, timeoutMs_);
        request_->SetPeerDeviceKey(peerDeviceKey_);
    }

protected:
    std::shared_ptr<MockOutboundRequest> request_;

    ScheduleId scheduleId_ = 1;
    uint32_t timeoutMs_ = 30000;
    DeviceKey peerDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "peer_device_id",
        .deviceUserId = 200 };
};

HWTEST_F(OutboundRequestTest, Start_001, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(true));

    request_->Start();
}

HWTEST_F(OutboundRequestTest, Start_002, TestSize.Level0)
{
    MockGuard guard;

    request_ = std::make_shared<MockOutboundRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, scheduleId_, timeoutMs_);

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(OutboundRequestTest, OnStart_001, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _)).WillOnce(Return(nullptr));

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
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, MessageType::REQUEST_ABORTED, _))
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
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillOnce(Return(false));

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
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    bool result = request_->Cancel(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(result);
}

HWTEST_F(OutboundRequestTest, Cancel_002, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();
    request_->cancelled_ = true;

    bool result = request_->Cancel(ResultCode::GENERAL_ERROR);

    EXPECT_TRUE(result);
}

HWTEST_F(OutboundRequestTest, SetPeerDeviceKey_001, TestSize.Level0)
{
    MockGuard guard;

    request_ = std::make_shared<MockOutboundRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, scheduleId_, timeoutMs_);

    request_->SetPeerDeviceKey(peerDeviceKey_);

    std::optional<DeviceKey> deviceKey = request_->GetPeerDeviceKey();
    EXPECT_TRUE(deviceKey.has_value());
    EXPECT_EQ(deviceKey->deviceId, peerDeviceKey_.deviceId);
}

HWTEST_F(OutboundRequestTest, CloseConnection_001, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();
    request_->connectionName_ = "test_connection";

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillOnce(Return());

    request_->CloseConnection();

    EXPECT_TRUE(request_->GetConnectionName().empty());
}

HWTEST_F(OutboundRequestTest, CloseConnection_002, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();
    request_->connectionName_ = "";

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).Times(0);

    request_->CloseConnection();
}

HWTEST_F(OutboundRequestTest, HandleConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    ASSERT_NE(request_, nullptr);

    request_->HandleConnectionStatus("test_connection", ConnectionStatus::ESTABLISHING, "establishing");
}

HWTEST_F(OutboundRequestTest, HandleConnectionStatus_002, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    EXPECT_CALL(*request_, OnConnected()).WillOnce(Return());

    request_->HandleConnectionStatus("test_connection", ConnectionStatus::CONNECTED, "connected");
}

HWTEST_F(OutboundRequestTest, HandleConnectionStatus_003, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    request_->HandleConnectionStatus("test_connection", ConnectionStatus::DISCONNECTED, "disconnected");
}

HWTEST_F(OutboundRequestTest, HandleConnectionStatus_004, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    request_->HandleConnectionStatus("test_connection", static_cast<ConnectionStatus>(999), "unknown");

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(OutboundRequestTest, HandleRequestAborted_001, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    Attributes request;
    RequestAbortedRequest abortReq;
    abortReq.result = ResultCode::TIMEOUT;
    abortReq.reason = "test_reason";
    EncodeRequestAbortedRequest(abortReq, request);

    bool replyCalled = false;
    OnMessageReply onReply = [&replyCalled](const Attributes &reply) { replyCalled = true; };

    request_->HandleRequestAborted(request, onReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(OutboundRequestTest, HandleRequestAborted_002, TestSize.Level0)
{
    MockGuard guard;

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _)).WillByDefault(Return(true));
    ON_CALL(guard.GetCrossDeviceCommManager(), CloseConnection(_)).WillByDefault(Return());

    CreateDefaultRequest();

    Attributes request;

    bool replyCalled = false;
    OnMessageReply onReply = [&replyCalled](const Attributes &reply) { replyCalled = true; };

    request_->HandleRequestAborted(request, onReply);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
