/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <optional>

#include "mock_guard.h"

#include "outbound_request.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint32_t REQUEST_TIMEOUT_MS = 60000;

const DeviceKey PEER_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "peer_device_id",
    .deviceUserId = 200 };

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

class TestOutboundRequest : public std::enable_shared_from_this<TestOutboundRequest>, public OutboundRequest {
public:
    TestOutboundRequest(ConnectionMode connectionMode, bool requiresSyncedDevice, bool hasPeer)
        : OutboundRequest(RequestType::HOST_TOKEN_AUTH_REQUEST, connectionMode, 0, REQUEST_TIMEOUT_MS),
          requiresSyncedDevice_(requiresSyncedDevice)
    {
        if (hasPeer) {
            SetPeerDeviceKey(PEER_DEVICE_KEY);
        }
    }

    // Route OnStart through the real connection-opening path (used by the
    // connection-status mapping tests).
    void UseRealOnStart()
    {
        useRealOnStart_ = true;
    }

    std::weak_ptr<OutboundRequest> GetWeakPtr() override
    {
        return shared_from_this();
    }

    bool RequireSyncedDevice() const override
    {
        return requiresSyncedDevice_;
    }

    void OnConnected() override
    {
    }

    uint32_t GetMaxConcurrency() const override
    {
        return 1;
    }

    bool ShouldCancelOnNewRequest(const IRequest &, uint32_t) const override
    {
        return false;
    }

    bool OnStart(ErrorGuard &errorGuard) override
    {
        ++onStartCount_;
        if (useRealOnStart_) {
            return OutboundRequest::OnStart(errorGuard);
        }
        return true;
    }

    void CompleteWithError(ResultCode result) override
    {
        completed_ = true;
        lastError_ = result;
    }

    int32_t GetOnStartCount() const
    {
        return onStartCount_;
    }

    bool IsCompletedWithError() const
    {
        return completed_;
    }

    ResultCode GetLastError() const
    {
        return lastError_;
    }

private:
    bool requiresSyncedDevice_;
    bool useRealOnStart_ = false;
    int32_t onStartCount_ = 0;
    bool completed_ = false;
    ResultCode lastError_ = ResultCode::GENERAL_ERROR;
};

class OutboundRequestTest : public testing::Test {
protected:
    // Captures the bring-online trigger and defers the settle, mirroring the real manager's
    // asynchronous sync result.
    struct BringOnlineCapture {
        PhysicalDeviceKey key {};
        std::optional<OnDeviceSyncResult> onResult;
    };

    void CaptureBringOnline(MockGuard &guard, BringOnlineCapture &capture)
    {
        ON_CALL(guard.GetCrossDeviceCommManager(), EnsureDeviceSynced(_, _))
            .WillByDefault(Invoke([&capture](const PhysicalDeviceKey &key, OnDeviceSyncResult &&onResult) {
                capture.key = key;
                capture.onResult = std::move(onResult);
            }));
    }

    // The request pins its peer with a demand subscription at its own connection mode; capture
    // what demand the pin actually carried.
    struct DemandPinCapture {
        DeviceKey deviceKey;
        SyncDemand demand { SyncDemand::NONE };
    };
    void CaptureDemandPin(MockGuard &guard, DemandPinCapture &capture)
    {
        ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
            .WillByDefault(Invoke([&capture](const DeviceKey &deviceKey, SyncDemand demand, OnDeviceStatusChange &&) {
                capture.deviceKey = deviceKey;
                capture.demand = demand;
                return MakeSubscription();
            }));
    }

    // Wires the mock manager for the real connection-opening path: settles bring-online inline
    // with SUCCESS, opens "test-conn" and captures the connection status callback.
    void SetupRealOpenPath(MockGuard &guard, OnConnectionStatusChange &statusCb)
    {
        ON_CALL(guard.GetCrossDeviceCommManager(), EnsureDeviceSynced(_, _))
            .WillByDefault(Invoke(
                [](const PhysicalDeviceKey &, OnDeviceSyncResult &&onResult) { onResult(ResultCode::SUCCESS); }));
        ON_CALL(guard.GetCrossDeviceCommManager(), OpenConnection(_, _, _))
            .WillByDefault(Invoke([](const DeviceKey &, ConnectionMode, std::string &outConnectionName) {
                outConnectionName = "test-conn";
                return true;
            }));
        ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
            .WillByDefault(Invoke([&statusCb](const std::string &, OnConnectionStatusChange &&onStatusChange) {
                statusCb = std::move(onStatusChange);
                return MakeSubscription();
            }));
        ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeMessage(_, _, _))
            .WillByDefault(Invoke([](const std::string &, MessageType, OnMessage &&) { return MakeSubscription(); }));
    }
};

// A request with a peer defers OnStart until the bring-online sync settles. The mode is no
// longer a trigger argument: the request pins its peer with a demand subscription at its own
// connection mode, and the ensure call carries only the physical key.
HWTEST_F(OutboundRequestTest, Start_WaitsForBringOnlineBeforeOnStart, TestSize.Level0)
{
    MockGuard guard;
    BringOnlineCapture capture;
    CaptureBringOnline(guard, capture);
    DemandPinCapture pin;
    CaptureDemandPin(guard, pin);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::FOREGROUND, true, true);
    request->Start();

    EXPECT_EQ(SyncDemand::FOREGROUND, pin.demand);
    EXPECT_EQ(PEER_DEVICE_KEY.deviceId, pin.deviceKey.deviceId);
    ASSERT_TRUE(capture.onResult.has_value());
    EXPECT_EQ(PEER_DEVICE_KEY.deviceId, capture.key.deviceId);
    EXPECT_EQ(0, request->GetOnStartCount());

    (*capture.onResult)(ResultCode::SUCCESS);

    EXPECT_EQ(1, request->GetOnStartCount());
    EXPECT_FALSE(request->IsCompletedWithError());
}

// A failed bring-online completes the request with the sync result code as-is: a coordinator
// rejection of the sync surfaces as COORDINATOR_REJECTED without ever reaching OnStart.
HWTEST_F(OutboundRequestTest, Start_BringOnlineFailureCompletesWithSyncResultCode, TestSize.Level0)
{
    MockGuard guard;
    BringOnlineCapture capture;
    CaptureBringOnline(guard, capture);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::BACKGROUND, true, true);
    request->Start();

    ASSERT_TRUE(capture.onResult.has_value());
    (*capture.onResult)(ResultCode::COORDINATOR_REJECTED);

    EXPECT_EQ(0, request->GetOnStartCount());
    EXPECT_TRUE(request->IsCompletedWithError());
    EXPECT_EQ(ResultCode::COORDINATOR_REJECTED, request->GetLastError());
}

// The sync request itself must not recursively bring its peer online: with RequireSyncedDevice
// disabled, Start skips the trigger and still reaches OnStart asynchronously.
HWTEST_F(OutboundRequestTest, Start_SkipsBringOnlineWhenPeerNotRequired, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), EnsureDeviceSynced(_, _)).Times(0);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::BACKGROUND, false, true);
    request->Start();

    EXPECT_EQ(0, request->GetOnStartCount());
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1, request->GetOnStartCount());
}

// The add request shape: the peer is not selected yet, so there is no key to bring online. The
// start flow continues asynchronously without any sync trigger.
HWTEST_F(OutboundRequestTest, Start_SkipsBringOnlineWhenPeerNotSelected, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), EnsureDeviceSynced(_, _)).Times(0);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::FOREGROUND, true, false);
    request->Start();

    EXPECT_EQ(0, request->GetOnStartCount());
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1, request->GetOnStartCount());
}

// Cancelling between Start and the queued RunOnStart must keep OnStart from running: the request
// is already finished, so re-opening the connection would recreate resources the preceding
// Destroy cannot clean up.
HWTEST_F(OutboundRequestTest, Start_CancelBeforeQueuedRunOnStart_SkipsOnStart, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), EnsureDeviceSynced(_, _)).Times(0);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::BACKGROUND, false, true);
    request->Start();

    EXPECT_EQ(0, request->GetOnStartCount());
    request->Cancel(ResultCode::CANCELED);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(0, request->GetOnStartCount());
    EXPECT_TRUE(request->IsCompletedWithError());
    EXPECT_EQ(ResultCode::CANCELED, request->GetLastError());
}

// A coordinator rejection arriving through the connection status pipeline completes the request
// with COORDINATOR_REJECTED, not the generic COMMUNICATION_ERROR.
HWTEST_F(OutboundRequestTest, HandleConnectionStatus_CoordinatorRejected_CompletesWithCoordinatorRejected,
    TestSize.Level0)
{
    MockGuard guard;
    OnConnectionStatusChange statusCb;
    SetupRealOpenPath(guard, statusCb);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::FOREGROUND, true, true);
    request->UseRealOnStart();
    request->Start();

    ASSERT_NE(statusCb, nullptr);
    EXPECT_EQ(1, request->GetOnStartCount());

    statusCb("test-conn", ConnectionStatus::DISCONNECTED, REASON_COORDINATOR_REJECTED);

    EXPECT_TRUE(request->IsCompletedWithError());
    EXPECT_EQ(ResultCode::COORDINATOR_REJECTED, request->GetLastError());
}

// peer_service_not_available keeps its dedicated result code through the disconnect path.
HWTEST_F(OutboundRequestTest, HandleConnectionStatus_PeerServiceNotAvailable_CompletesWithCode, TestSize.Level0)
{
    MockGuard guard;
    OnConnectionStatusChange statusCb;
    SetupRealOpenPath(guard, statusCb);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::BACKGROUND, true, true);
    request->UseRealOnStart();
    request->Start();

    ASSERT_NE(statusCb, nullptr);

    statusCb("test-conn", ConnectionStatus::DISCONNECTED, REASON_PEER_SERVICE_NOT_AVAILABLE);

    EXPECT_TRUE(request->IsCompletedWithError());
    EXPECT_EQ(ResultCode::PEER_SERVICE_NOT_AVAILABLE, request->GetLastError());
}

// An arbitration timeout keeps TIMEOUT as its result code: the request died
// waiting for the coordinator, which is a timeout in every observable sense.
HWTEST_F(OutboundRequestTest, HandleConnectionStatus_ArbitrationTimeout_CompletesWithTimeout, TestSize.Level0)
{
    MockGuard guard;
    OnConnectionStatusChange statusCb;
    SetupRealOpenPath(guard, statusCb);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::FOREGROUND, true, true);
    request->UseRealOnStart();
    request->Start();

    ASSERT_NE(statusCb, nullptr);

    statusCb("test-conn", ConnectionStatus::DISCONNECTED, REASON_COORDINATOR_TIMEOUT);

    EXPECT_TRUE(request->IsCompletedWithError());
    EXPECT_EQ(ResultCode::TIMEOUT, request->GetLastError());
}

// Any other disconnect reason collapses to COMMUNICATION_ERROR.
HWTEST_F(OutboundRequestTest, HandleConnectionStatus_OtherReason_CompletesWithCommunicationError, TestSize.Level0)
{
    MockGuard guard;
    OnConnectionStatusChange statusCb;
    SetupRealOpenPath(guard, statusCb);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::BACKGROUND, true, true);
    request->UseRealOnStart();
    request->Start();

    ASSERT_NE(statusCb, nullptr);

    statusCb("test-conn", ConnectionStatus::DISCONNECTED, "remote_closed");

    EXPECT_TRUE(request->IsCompletedWithError());
    EXPECT_EQ(ResultCode::COMMUNICATION_ERROR, request->GetLastError());
}

// A coordinator revocation (disconnect_requested) is retriable by design: it completes with
// COMMUNICATION_ERROR through its own explicit branch, not by falling through the default.
HWTEST_F(OutboundRequestTest, HandleConnectionStatus_DisconnectRequested_CompletesWithCommunicationError,
    TestSize.Level0)
{
    MockGuard guard;
    OnConnectionStatusChange statusCb;
    SetupRealOpenPath(guard, statusCb);

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::BACKGROUND, true, true);
    request->UseRealOnStart();
    request->Start();

    ASSERT_NE(statusCb, nullptr);

    statusCb("test-conn", ConnectionStatus::DISCONNECTED, REASON_DISCONNECT_REQUESTED);

    EXPECT_TRUE(request->IsCompletedWithError());
    EXPECT_EQ(ResultCode::COMMUNICATION_ERROR, request->GetLastError());
}

// A failed demand subscription aborts bring-online with COMMUNICATION_ERROR instead of
// proceeding and settling later with a misleading GENERAL_ERROR from the missing demand.
HWTEST_F(OutboundRequestTest, Start_FailedDemandSubscription_CompletesWithCommunicationError, TestSize.Level0)
{
    MockGuard guard;
    BringOnlineCapture bringOnline;
    CaptureBringOnline(guard, bringOnline);
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeDeviceStatus(_, _, _))
        .WillByDefault(Invoke([](const DeviceKey &, SyncDemand, OnDeviceStatusChange &&) {
            return std::unique_ptr<Subscription>(nullptr);
        }));

    auto request = std::make_shared<TestOutboundRequest>(ConnectionMode::FOREGROUND, true, true);
    request->Start();
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(request->IsCompletedWithError());
    EXPECT_EQ(ResultCode::COMMUNICATION_ERROR, request->GetLastError());
    EXPECT_EQ(0, request->GetOnStartCount());
    EXPECT_FALSE(bringOnline.onResult.has_value());
}
} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
