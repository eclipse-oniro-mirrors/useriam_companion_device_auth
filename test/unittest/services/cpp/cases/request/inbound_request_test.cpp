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

#include "inbound_request.h"
#include "request_aborted_message.h"
#include "service_common.h"
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

class MockInboundRequest : public InboundRequest {
public:
    MockInboundRequest(RequestType requestType, const std::string &connectionName, const DeviceKey &peerDeviceKey)
        : InboundRequest(requestType, connectionName, peerDeviceKey)
    {
    }

    MOCK_METHOD(bool, OnStart, (ErrorGuard & errorGuard), (override));
    MOCK_METHOD(std::weak_ptr<InboundRequest>, GetWeakPtr, (), (override));
    MOCK_METHOD(void, CompleteWithError, (ResultCode result), (override));
    MOCK_METHOD(uint32_t, GetMaxConcurrency, (), (const, override));
    MOCK_METHOD(bool, ShouldCancelOnNewRequest,
        (RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice, uint32_t subsequentSameTypeCount),
        (const, override));
};

class InboundRequestTest : public Test {
public:
    void CreateDefaultRequest()
    {
        request_ = std::make_shared<MockInboundRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, connectionName_,
            peerDeviceKey_);
    }

protected:
    std::shared_ptr<MockInboundRequest> request_;

    std::string connectionName_ = "test_connection";
    DeviceKey peerDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "peer_device_id",
        .deviceUserId = 200 };
};

HWTEST_F(InboundRequestTest, Start_001, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(connectionName_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(connectionName_))
        .WillOnce(Return(ConnectionStatus::CONNECTED));
    EXPECT_CALL(*request_, OnStart(_)).WillOnce(Return(true));

    request_->Start();
}

HWTEST_F(InboundRequestTest, Start_002, TestSize.Level0)
{
    MockGuard guard;

    request_ = std::make_shared<MockInboundRequest>(RequestType::HOST_DELEGATE_AUTH_REQUEST, "", peerDeviceKey_);

    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(InboundRequestTest, Start_003, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(connectionName_, _))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(InboundRequestTest, Start_004, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(connectionName_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(connectionName_))
        .WillOnce(Return(ConnectionStatus::DISCONNECTED));
    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(InboundRequestTest, Start_005, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(connectionName_, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(connectionName_))
        .WillOnce(Return(ConnectionStatus::CONNECTED));
    EXPECT_CALL(*request_, OnStart(_)).WillOnce(Return(false));
    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    request_->Start();

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(InboundRequestTest, Cancel_001, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(connectionName_, MessageType::REQUEST_ABORTED, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    bool result = request_->Cancel(ResultCode::GENERAL_ERROR);

    EXPECT_TRUE(result);
}

HWTEST_F(InboundRequestTest, Cancel_002, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    request_->cancelled_ = true;
    bool result = request_->Cancel(ResultCode::GENERAL_ERROR);

    EXPECT_TRUE(result);
}

HWTEST_F(InboundRequestTest, GetPeerDeviceKey_001, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    std::optional<DeviceKey> deviceKey = request_->GetPeerDeviceKey();

    EXPECT_TRUE(deviceKey.has_value());
    EXPECT_EQ(deviceKey->deviceId, peerDeviceKey_.deviceId);
}

HWTEST_F(InboundRequestTest, PeerDeviceKey_001, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    const DeviceKey &deviceKey = request_->PeerDeviceKey();

    EXPECT_EQ(deviceKey.deviceId, peerDeviceKey_.deviceId);
    EXPECT_EQ(deviceKey.deviceUserId, peerDeviceKey_.deviceUserId);
}

HWTEST_F(InboundRequestTest, GetConnectionName_001, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    const std::string &connName = request_->GetConnectionName();

    EXPECT_EQ(connName, connectionName_);
}

HWTEST_F(InboundRequestTest, HandleConnectionStatus_001, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    ASSERT_NE(request_, nullptr);

    request_->HandleConnectionStatus(connectionName_, ConnectionStatus::ESTABLISHING, "establishing");
}

HWTEST_F(InboundRequestTest, HandleConnectionStatus_002, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    ASSERT_NE(request_, nullptr);

    request_->HandleConnectionStatus(connectionName_, ConnectionStatus::CONNECTED, "connected");
}

HWTEST_F(InboundRequestTest, HandleConnectionStatus_003, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    EXPECT_CALL(*request_, CompleteWithError(_)).WillOnce(Return());

    request_->HandleConnectionStatus(connectionName_, ConnectionStatus::DISCONNECTED, "disconnected");
}

HWTEST_F(InboundRequestTest, HandleConnectionStatus_004, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    ASSERT_NE(request_, nullptr);

    request_->HandleConnectionStatus(connectionName_, static_cast<ConnectionStatus>(999), "unknown");

    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(InboundRequestTest, CompleteWithError_001, TestSize.Level0)
{
    MockGuard guard;

    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Return(ByMove(MakeSubscription())));
    ON_CALL(guard.GetCrossDeviceCommManager(), GetConnectionStatus(_))
        .WillByDefault(Return(ConnectionStatus::CONNECTED));
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(true));

    CreateDefaultRequest();

    request_->CompleteWithError(ResultCode::GENERAL_ERROR);

    TaskRunnerManager::GetInstance().ExecuteAll();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
