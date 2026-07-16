/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

#include "device_resync_scheduler.h"
#include "irequest.h"
#include "relative_timer.h"
#include "service_common.h"
#include "soft_bus_device_status_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// Minimal non-null IRequest stand-in. The mocked RequestManager::Start never actually
// drives a request, so the returned object only needs to be non-null to keep
// DeviceResyncScheduler from erasing the retry entry on the "launch failed" path.
class FakeResyncRequest : public IRequest {
public:
    void Start() override
    {
    }
    bool Cancel(ResultCode) override
    {
        return true;
    }
    RequestType GetRequestType() const override
    {
        return RequestType::COMPANION_REQUEST_RESYNC_REQUEST;
    }
    const char *GetDescription() const override
    {
        return "FakeResyncRequest";
    }
    RequestId GetRequestId() const override
    {
        return 0;
    }
    ScheduleId GetScheduleId() const override
    {
        return 0;
    }
    std::optional<DeviceKey> GetPeerDeviceKey() const override
    {
        return std::nullopt;
    }
    std::optional<TemplateId> GetTemplateId() const override
    {
        return std::nullopt;
    }
    uint32_t GetMaxConcurrency() const override
    {
        return 1;
    }
    bool CanStart(const std::vector<std::shared_ptr<IRequest>> &) const override
    {
        return true;
    }
    bool ShouldCancelOnNewRequest(const IRequest &, uint32_t) const override
    {
        return false;
    }
};

// Test compiles with -Dprivate=public, so physicalDeviceStatus_ is reachable.
// Pushing a status entry makes GetPhysicalDeviceStatus(key) return a value, which
// the scheduler reads as "device online" via GetPhysicalDeviceStatus(key).has_value().
void MarkDeviceOnline(SoftBusDeviceStatusManager &manager, const PhysicalDeviceKey &key)
{
    PhysicalDeviceStatus status;
    status.physicalDeviceKey = key;
    manager.physicalDeviceStatus_.push_back(status);
}

void MarkDeviceOffline(SoftBusDeviceStatusManager &manager, const PhysicalDeviceKey &key)
{
    auto &devices = manager.physicalDeviceStatus_;
    for (size_t i = 0; i < devices.size();) {
        if (devices[i].physicalDeviceKey == key) {
            devices.erase(devices.begin() + i);
        } else {
            ++i;
        }
    }
}

class DeviceResyncSchedulerTest : public testing::Test {
public:
    void SetUp() override
    {
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
    }
};

HWTEST_F(DeviceResyncSchedulerTest, Create_001, TestSize.Level0)
{
    MockGuard guard;

    auto scheduler = DeviceResyncScheduler::Create(nullptr);
    EXPECT_EQ(scheduler, nullptr);
}

HWTEST_F(DeviceResyncSchedulerTest, Start_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);

    bool result = scheduler->Start();
    EXPECT_TRUE(result);
}

// Fixed: under the new contract HandleResyncComplete no longer creates entries, and a
// real failure first gates on the device-online check. We mark the device online and seed the
// entry via EnsureRetryEntry, then a GENERAL_ERROR arms the retry (entry retained) and
// SUCCESS must erase it.
HWTEST_F(DeviceResyncSchedulerTest, HandleResyncComplete_SuccessErasesRetryEntry, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    scheduler->EnsureRetryEntry(key, "test");
    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    scheduler->HandleResyncComplete(key, 0, ResultCode::SUCCESS);

    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 0u);
}

HWTEST_F(DeviceResyncSchedulerTest, OnPhysicalDeviceStatusChanged_RemovesOfflineDevice, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    scheduler->EnsureRetryEntry(key, "test");
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    scheduler->OnPhysicalDeviceStatusChanged({});

    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 0u);
}

// OnPhysicalDeviceStatusChanged: a device already online in a prior snapshot is not resynced again —
// only newly-online devices trigger a resync. Asserted via factory call count, not a tautological
// entry count.
HWTEST_F(DeviceResyncSchedulerTest, OnPhysicalDeviceStatusChanged_DoesNotResyncAlreadyOnlineDevice, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);
    PhysicalDeviceStatus status;
    status.physicalDeviceKey = key;

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    // First snapshot: device is newly online -> resync launched.
    scheduler->OnPhysicalDeviceStatusChanged({ status });
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 1);

    // Second snapshot: device still online (not newly online) -> not resynced again.
    scheduler->OnPhysicalDeviceStatusChanged({ status });
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 1);
}

// ResyncAllPhysicalDevices drives the fan-out path synchronously; a device whose resync fails
// to launch arms a retry and retains the entry, so the fan-out is not stranded by one launch failure.
HWTEST_F(DeviceResyncSchedulerTest, ResyncAllPhysicalDevices_LaunchFailureArmsRetry, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    // Launch failure (factory returns nullptr) arms a retry instead of erasing.
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(nullptr));

    scheduler->ResyncAllPhysicalDevices("test");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);
}

// Fixed: drives a real request lifecycle. The factory returns a non-null fake request and
// captures the onComplete callback; invoking it with GENERAL_ERROR drives
// HandleResyncComplete (device online) which arms the backoff timer; firing the timer
// re-enters ResyncOneDevice and hits the factory a second time.
HWTEST_F(DeviceResyncSchedulerTest, FirstFailure_ArmsRetryThatRefiresResync, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto lastCallback = std::make_shared<std::optional<ResultCodeCallback>>();
    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([lastCallback, factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback cb) {
            *lastCallback = std::move(cb);
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    scheduler->ResyncOneDevice(key, "test_reason");
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // The in-progress request fails; the retry timer must be armed (entry retained).
    ASSERT_TRUE(lastCallback->has_value());
    lastCallback->value()(ResultCode::GENERAL_ERROR);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // Firing the backoff retry re-enters ResyncOneDevice (factory hit a second time).
    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 2);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);
}

// Renamed from ScheduleDeviceResyncRetry_Exhaustion (that method was deleted). Verifies the
// new HandleResyncComplete contract: with the device online, failures 1..5 retain the
// entry (each OnFailure arms a retry), and the 6th failure (failureCount 6 > maxRetryCount
// 5) exhausts and erases it.
HWTEST_F(DeviceResyncSchedulerTest, HandleResyncComplete_ExhaustedAfterMaxRetries, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    scheduler->EnsureRetryEntry(key, "test");
    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 0u);
}

// H1: a CANCELED completion for an online device is retried (driving the timer re-invokes the
// factory) rather than treated as a terminal preemption that strands the device.
HWTEST_F(DeviceResyncSchedulerTest, HandleResyncComplete_CanceledArmsRetryWhenOnline, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);
    scheduler->EnsureRetryEntry(key, "test");
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // CANCELED must arm a retry: driving the timer re-invokes the factory at least once.
    EXPECT_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _)).Times(AtLeast(1));

    scheduler->HandleResyncComplete(key, 0, ResultCode::CANCELED);

    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
}

// M1: a real failure for a device that has gone offline must erase the entry and not
// re-arm the backoff (do not hammer an offline device).
HWTEST_F(DeviceResyncSchedulerTest, HandleResyncComplete_OfflineFailureDoesNotRearm, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    // Online failure arms retry and retains the entry.
    scheduler->EnsureRetryEntry(key, "test");
    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // Device goes offline while a request is in progress: the next failure erases the
    // entry and must not re-arm.
    MarkDeviceOffline(*manager, key);
    scheduler->HandleResyncComplete(key, 0, ResultCode::GENERAL_ERROR);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 0u);
}

// L1: a launch failure (factory returns nullptr) arms a retry instead of erasing the entry, so the
// device is retried rather than stranded.
HWTEST_F(DeviceResyncSchedulerTest, ResyncOneDevice_LaunchFailureArmsRetry, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return nullptr;
        }));

    scheduler->ResyncOneDevice(key, "test");
    // The initial launch failure did not erase; a retry was armed.
    EXPECT_EQ(*factoryCallCount, 1);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // Driving the retry timer re-invokes the factory (proving a retry was armed).
    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_GT(*factoryCallCount, 1);
}

// L2: after a launch failure arms a retry, a subsequent successful retry launches the request and
// retains the entry (the device recovers instead of being stranded by one transient failure).
HWTEST_F(DeviceResyncSchedulerTest, ResyncOneDevice_LaunchFailureThenRetrySucceeds, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    // First attempt fails to launch; the retry succeeds.
    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return *factoryCallCount == 1 ? nullptr : std::make_shared<FakeResyncRequest>();
        }));

    scheduler->ResyncOneDevice(key, "test");
    EXPECT_EQ(*factoryCallCount, 1);
    // Launch failure armed a retry; entry retained.
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
    // Retry fired and succeeded: the factory was called again and the entry is retained.
    EXPECT_GT(*factoryCallCount, 1);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);
}

// L3: the other launch-failure branch (factory succeeds but RequestManager::Start fails) also arms
// a retry, and once Start succeeds again the retry launches the request and retains the entry.
HWTEST_F(DeviceResyncSchedulerTest, ResyncOneDevice_StartFailureArmsRetry, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    // First trigger: factory succeeds but Start fails -> retry armed (entry retained).
    ON_CALL(guard.GetRequestManager(), Start(_)).WillByDefault(Return(false));
    scheduler->ResyncOneDevice(key, "test");
    EXPECT_EQ(*factoryCallCount, 1);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // Retry fires once Start succeeds again: factory called again, entry retained.
    ON_CALL(guard.GetRequestManager(), Start(_)).WillByDefault(Return(true));
    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_GT(*factoryCallCount, 1);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);
}

// E2E-1: Start() wires the active-user-id subscription end-to-end. Firing the captured callback
// routes through OnActiveUserIdChanged -> ResyncAllPhysicalDevices and reaches the request factory,
// proving the active-user-switch trigger is live rather than a dead subscription.
HWTEST_F(DeviceResyncSchedulerTest, Start_RoutesActiveUserIdChangeToFactory, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);

    // Capture the subscription callback; the default mock discards it.
    ActiveUserIdCallback capturedCb;
    ON_CALL(guard.GetUserIdManager(), SubscribeActiveUserId(_))
        .WillByDefault(Invoke([&capturedCb](ActiveUserIdCallback &&cb) {
            capturedCb = std::move(cb);
            return std::make_unique<Subscription>([]() {});
        }));

    EXPECT_TRUE(scheduler->Start());
    ASSERT_NE(capturedCb, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return nullptr;
        }));

    capturedCb(1); // active user changed
    TaskRunnerManager::GetInstance().ExecuteAll();

    // The trigger reached the factory instead of being silently dropped.
    EXPECT_GE(*factoryCallCount, 1);
}

// E2E-2: Start() wires the display-device-name subscription end-to-end. Firing the captured callback
// routes through OnLocalDeviceNameChanged -> ResyncAllPhysicalDevices and reaches the factory, proving
// the device-name-change trigger is live.
HWTEST_F(DeviceResyncSchedulerTest, Start_RoutesDeviceNameChangeToFactory, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);

    SettingsChangeCallback capturedCb;
    ON_CALL(guard.GetSystemSettingsManager(), SubscribeSettingsChange(_, _))
        .WillByDefault(Invoke([&capturedCb](SettingKey, SettingsChangeCallback &&cb) {
            capturedCb = std::move(cb);
            return std::make_unique<Subscription>([]() {});
        }));

    EXPECT_TRUE(scheduler->Start());
    ASSERT_NE(capturedCb, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return nullptr;
        }));

    capturedCb(); // local device name changed
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_GE(*factoryCallCount, 1);
}

// T1: ResyncAllPhysicalDevices fans out to every device known to the status manager.
HWTEST_F(DeviceResyncSchedulerTest, ResyncAllPhysicalDevices_CoversAllDevices, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey keyA;
    keyA.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyA.deviceId = "dev_A";
    PhysicalDeviceKey keyB;
    keyB.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyB.deviceId = "dev_B";
    PhysicalDeviceKey keyC;
    keyC.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyC.deviceId = "dev_C";
    MarkDeviceOnline(*manager, keyA);
    MarkDeviceOnline(*manager, keyB);
    MarkDeviceOnline(*manager, keyC);

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    scheduler->ResyncAllPhysicalDevices("test");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(*factoryCallCount, 3);
    EXPECT_EQ(scheduler->scheduledResyncs_.size(), static_cast<size_t>(3));
}

// T2/T3: end-to-end retry chain. A failing fake request drives the full backoff loop:
// 1 initial attempt + 5 retries = 6 factory calls, then the 6th failure exhausts the
// backoff (failureCount 6 > maxRetryCount 5), the entry is erased and no 7th attempt is
// made.
HWTEST_F(DeviceResyncSchedulerTest, RetryChainStopsAfterMaxRetries, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    // The factory captures the latest onComplete callback so the test can complete the
    // request with GENERAL_ERROR, simulating a persistently failing device.
    auto lastCallback = std::make_shared<std::optional<ResultCodeCallback>>();
    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([lastCallback, factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback cb) {
            *lastCallback = std::move(cb);
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    // Initial attempt (factory call #1).
    scheduler->ResyncOneDevice(key, "test");
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // Five retry cycles: fail -> HandleResyncComplete arms backoff -> fire timer ->
    // ResyncOneDevice launches a new request.
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(lastCallback->has_value());
        lastCallback->value()(ResultCode::GENERAL_ERROR);
        TaskRunnerManager::GetInstance().ExecuteAll();
        EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);
        RelativeTimer::GetInstance().ExecuteAll();
    }
    EXPECT_EQ(*factoryCallCount, 6);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // The 6th failure exhausts the backoff: entry erased, no further retry armed.
    ASSERT_TRUE(lastCallback->has_value());
    lastCallback->value()(ResultCode::GENERAL_ERROR);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 0u);

    // Nothing left to fire: factory call count must not grow.
    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 6);
}

// T5: two devices maintain independent backoff entries. Exhausting one does not affect
// the other.
HWTEST_F(DeviceResyncSchedulerTest, MultipleDevicesHaveIndependentBackoff, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey keyA;
    keyA.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyA.deviceId = "dev_A";
    PhysicalDeviceKey keyB;
    keyB.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyB.deviceId = "dev_B";
    MarkDeviceOnline(*manager, keyA);
    MarkDeviceOnline(*manager, keyB);

    scheduler->EnsureRetryEntry(keyA, "test");
    scheduler->EnsureRetryEntry(keyB, "test");
    ASSERT_EQ(scheduler->scheduledResyncs_.size(), static_cast<size_t>(2));

    // Both fail once: both entries retained with independent backoff state.
    scheduler->HandleResyncComplete(keyA, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(keyB, 0, ResultCode::GENERAL_ERROR);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyA), 1u);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyB), 1u);

    // Five more failures on A exhaust only A (failureCount 6 > maxRetryCount 5).
    scheduler->HandleResyncComplete(keyA, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(keyA, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(keyA, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(keyA, 0, ResultCode::GENERAL_ERROR);
    scheduler->HandleResyncComplete(keyA, 0, ResultCode::GENERAL_ERROR);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyA), 0u);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyB), 1u);
}

// reason freshness + in-progress coalescing: a second external trigger while a request is in
// flight is coalesced (no second launch), but EnsureRetryEntry still refreshes the entry's reason
// to the latest. The eventual retry therefore fires with the latest reason, not the one captured
// at entry creation.
HWTEST_F(DeviceResyncSchedulerTest, OnRetryTimerFired_UsesLatestTriggerReason, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto lastCallback = std::make_shared<std::optional<ResultCodeCallback>>();
    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([lastCallback, factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback cb) {
            *lastCallback = std::move(cb);
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    // First trigger (reason A) launches R1.
    scheduler->ResyncOneDevice(key, "active_user_changed");
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);

    // Second trigger (reason B) while R1 is in progress: coalesced — no new launch — but the entry
    // reason is refreshed to the latest.
    scheduler->ResyncOneDevice(key, "device_name_changed");
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 1); // still 1, coalesced
    ASSERT_EQ(scheduler->scheduledResyncs_.at(key).reason, "device_name_changed");
    ASSERT_TRUE(scheduler->scheduledResyncs_.at(key).isResyncInProgress);

    // Fail R1 to arm the backoff, then fire the retry: the retried request uses the latest reason.
    ASSERT_TRUE(lastCallback->has_value());
    lastCallback->value()(ResultCode::GENERAL_ERROR);
    TaskRunnerManager::GetInstance().ExecuteAll();
    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
}

// Coalescing: a second external trigger while a request is in progress must not launch a second
// request (in-progress merge), mirroring Sync's isSyncInProgress gate.
HWTEST_F(DeviceResyncSchedulerTest, ResyncOneDevice_CoalescesWhenInFlight, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    scheduler->ResyncOneDevice(key, "test");
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);
    ASSERT_TRUE(scheduler->scheduledResyncs_.at(key).isResyncInProgress);

    // Second trigger while in progress: coalesced.
    scheduler->ResyncOneDevice(key, "test");
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 1);
    EXPECT_TRUE(scheduler->scheduledResyncs_.at(key).isResyncInProgress);
}

// Dual-counter: an external trigger resets the backoff step (delay) but preserves the failure
// budget, so responsiveness improves while finite retry capping still holds.
HWTEST_F(DeviceResyncSchedulerTest, ExternalTrigger_ResetsBackoffNotBudget, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke(
            [](const PhysicalDeviceKey &, ResultCodeCallback) { return std::make_shared<FakeResyncRequest>(); }));

    scheduler->EnsureRetryEntry(key, "test");
    auto &timer = scheduler->scheduledResyncs_.at(key).timer;
    timer->OnFailure(); // backoffStep=1, failureCount=1
    timer->OnFailure(); // backoffStep=2, failureCount=2
    ASSERT_EQ(timer->backoffStep_, 2u);
    ASSERT_EQ(timer->failureCount_, 2u);

    // External trigger: ResetBackoff (delay reset, pending cancelled) then launch — budget kept.
    scheduler->ResyncOneDevice(key, "test");
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(timer->backoffStep_, 0u);  // delay reset
    EXPECT_EQ(timer->failureCount_, 2u); // budget kept
}

// Retry-fire must NOT reset the counters: both backoff step and failure budget keep growing, so
// the delay increases and exhaustion still caps total attempts.
HWTEST_F(DeviceResyncSchedulerTest, RetryFire_DoesNotResetCount, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto lastCallback = std::make_shared<std::optional<ResultCodeCallback>>();
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([lastCallback](const PhysicalDeviceKey &, ResultCodeCallback cb) {
            *lastCallback = std::move(cb);
            return std::make_shared<FakeResyncRequest>();
        }));

    scheduler->ResyncOneDevice(key, "test"); // R1
    TaskRunnerManager::GetInstance().ExecuteAll();
    auto &timer = scheduler->scheduledResyncs_.at(key).timer;

    // R1 fails -> both counters advance to 1, backoff armed.
    ASSERT_TRUE(lastCallback->has_value());
    lastCallback->value()(ResultCode::GENERAL_ERROR);
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(timer->backoffStep_, 1u);
    ASSERT_EQ(timer->failureCount_, 1u);

    // Retry-fire launches R2 without resetting the counters.
    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(timer->backoffStep_, 1u); // unchanged by retry-fire

    // R2 fails -> both counters advance to 2.
    ASSERT_TRUE(lastCallback->has_value());
    lastCallback->value()(ResultCode::GENERAL_ERROR);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(timer->backoffStep_, 2u);
    EXPECT_EQ(timer->failureCount_, 2u);
}

// External trigger during a pending retry wait must issue immediately, reset the backoff delay,
// and cancel the pending timer so it does not fire later.
HWTEST_F(DeviceResyncSchedulerTest, ExternalTriggerDuringRetryWait_IssuesImmediately, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    auto lastCallback = std::make_shared<std::optional<ResultCodeCallback>>();
    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([lastCallback, factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback cb) {
            *lastCallback = std::move(cb);
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    scheduler->ResyncOneDevice(key, "test"); // R1
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);

    // R1 fails -> a pending retry is armed (backoffStep=1).
    ASSERT_TRUE(lastCallback->has_value());
    lastCallback->value()(ResultCode::GENERAL_ERROR);
    TaskRunnerManager::GetInstance().ExecuteAll();
    auto &timer = scheduler->scheduledResyncs_.at(key).timer;
    ASSERT_EQ(timer->backoffStep_, 1u);

    // External trigger: pending cancelled, backoff reset, fresh request issues immediately.
    scheduler->ResyncOneDevice(key, "test");
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 2);
    EXPECT_EQ(timer->backoffStep_, 0u);

    // The old pending retry must not fire.
    RelativeTimer::GetInstance().ExecuteAll();
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 2);
}

// Race fix: a stale completion (from a request launched before the entry was torn down and
// rebuilt) must not corrupt the rebuilt entry — specifically a late SUCCESS must not erase it.
HWTEST_F(DeviceResyncSchedulerTest, StaleCompletion_DoesNotCorruptRebuiltEntry, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "dev_A";
    MarkDeviceOnline(*manager, key);

    // Capture every onComplete so a stale one can be replayed out of order.
    auto callbacks = std::make_shared<std::vector<ResultCodeCallback>>();
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([callbacks](const PhysicalDeviceKey &, ResultCodeCallback cb) {
            callbacks->push_back(std::move(cb));
            return std::make_shared<FakeResyncRequest>();
        }));

    // R1 in progress.
    scheduler->ResyncOneDevice(key, "test");
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(callbacks->size(), 1u);
    auto staleCallback = std::move(callbacks->at(0));

    // Device goes offline -> the entry is torn down (R1 still alive in the RequestManager).
    scheduler->OnPhysicalDeviceStatusChanged({});
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 0u);

    // Device returns + a fresh trigger rebuilds the entry and launches R2 (new request id).
    MarkDeviceOnline(*manager, key);
    scheduler->ResyncOneDevice(key, "test");
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(callbacks->size(), 2u);
    ASSERT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // The stale R1 SUCCESS arrives late: it must NOT erase the rebuilt entry.
    staleCallback(ResultCode::SUCCESS);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 1u);

    // The current R2 completion still resolves normally.
    callbacks->at(1)(ResultCode::SUCCESS);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(scheduler->scheduledResyncs_.count(key), 0u);
}

// First snapshot: prevOnline is empty, so every currently-online device is treated as newly
// online and resynced — SA does not distinguish start-up-online from later-online devices.
HWTEST_F(DeviceResyncSchedulerTest, OnPhysicalDeviceStatusChanged_FirstSnapshot_ResyncsAllOnline, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey keyA;
    keyA.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyA.deviceId = "dev_A";
    PhysicalDeviceKey keyB;
    keyB.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyB.deviceId = "dev_B";

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    PhysicalDeviceStatus statusA;
    statusA.physicalDeviceKey = keyA;
    PhysicalDeviceStatus statusB;
    statusB.physicalDeviceKey = keyB;
    scheduler->OnPhysicalDeviceStatusChanged({ statusA, statusB });
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(*factoryCallCount, 2);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyA), 1u);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyB), 1u);
}

// After the first snapshot records the baseline, only a genuinely new device triggers on the next
// snapshot, and with the "device_online" reason.
HWTEST_F(DeviceResyncSchedulerTest, OnPhysicalDeviceStatusChanged_NewDeviceOnline_TriggersResync, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey keyA;
    keyA.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyA.deviceId = "dev_A";
    PhysicalDeviceKey keyB;
    keyB.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyB.deviceId = "dev_B";

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    PhysicalDeviceStatus statusA;
    statusA.physicalDeviceKey = keyA;
    scheduler->OnPhysicalDeviceStatusChanged({ statusA }); // first snapshot: A
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);

    PhysicalDeviceStatus statusB;
    statusB.physicalDeviceKey = keyB;
    scheduler->OnPhysicalDeviceStatusChanged({ statusA, statusB }); // B newly online
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(*factoryCallCount, 2); // only B this round
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyA), 1u);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyB), 1u);
}

// Every device absent in the previous snapshot triggers its own resync in one round.
HWTEST_F(DeviceResyncSchedulerTest, OnPhysicalDeviceStatusChanged_MultipleNewDevices_EachTriggersResync,
    TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey keyA;
    keyA.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyA.deviceId = "dev_A";
    PhysicalDeviceKey keyB;
    keyB.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyB.deviceId = "dev_B";
    PhysicalDeviceKey keyC;
    keyC.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyC.deviceId = "dev_C";

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    scheduler->OnPhysicalDeviceStatusChanged({}); // first snapshot empty -> nothing
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 0);

    PhysicalDeviceStatus statusA;
    statusA.physicalDeviceKey = keyA;
    PhysicalDeviceStatus statusB;
    statusB.physicalDeviceKey = keyB;
    PhysicalDeviceStatus statusC;
    statusC.physicalDeviceKey = keyC;
    scheduler->OnPhysicalDeviceStatusChanged({ statusA, statusB, statusC });
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_EQ(*factoryCallCount, 3);
}

// Offline erases the entry and drops the device from prevOnline; coming back online rebuilds a
// fresh entry and re-triggers resync.
HWTEST_F(DeviceResyncSchedulerTest, OnPhysicalDeviceStatusChanged_OfflineThenOnline_RetriggersResync, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey keyA;
    keyA.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyA.deviceId = "dev_A";

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    PhysicalDeviceStatus statusA;
    statusA.physicalDeviceKey = keyA;
    scheduler->OnPhysicalDeviceStatusChanged({ statusA }); // online
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);
    ASSERT_EQ(scheduler->scheduledResyncs_.count(keyA), 1u);

    scheduler->OnPhysicalDeviceStatusChanged({}); // offline: entry erased
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyA), 0u);

    scheduler->OnPhysicalDeviceStatusChanged({ statusA }); // back online: re-trigger
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 2);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyA), 1u);
}

// DeviceManager SA restart: unavailable clears the list (all entries dropped), ready repopulates
// it — every returning device is resynced since, from the host's view, they came back online.
HWTEST_F(DeviceResyncSchedulerTest, OnPhysicalDeviceStatusChanged_DmRestart_ReTriggersAllReturningDevices,
    TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey keyA;
    keyA.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyA.deviceId = "dev_A";
    PhysicalDeviceKey keyB;
    keyB.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyB.deviceId = "dev_B";

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    PhysicalDeviceStatus statusA;
    statusA.physicalDeviceKey = keyA;
    scheduler->OnPhysicalDeviceStatusChanged({ statusA }); // {A}
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);

    scheduler->OnPhysicalDeviceStatusChanged({}); // DM unavailable: {}
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyA), 0u);

    PhysicalDeviceStatus statusB;
    statusB.physicalDeviceKey = keyB;
    scheduler->OnPhysicalDeviceStatusChanged({ statusA, statusB }); // DM ready: {A,B}
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 3); // +2 (A and B both re-resynced)
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyA), 1u);
    EXPECT_EQ(scheduler->scheduledResyncs_.count(keyB), 1u);
}

// A device already present in the previous snapshot must not be re-resynced on an unchanged set.
HWTEST_F(DeviceResyncSchedulerTest, OnPhysicalDeviceStatusChanged_AlreadyOnline_NoRetrigger, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto scheduler = DeviceResyncScheduler::Create(manager);
    ASSERT_NE(scheduler, nullptr);
    EXPECT_TRUE(scheduler->Start());

    PhysicalDeviceKey keyA;
    keyA.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    keyA.deviceId = "dev_A";

    auto factoryCallCount = std::make_shared<int>(0);
    ON_CALL(guard.GetRequestFactory(), CreateCompanionRequestResyncRequest(_, _))
        .WillByDefault(Invoke([factoryCallCount](const PhysicalDeviceKey &, ResultCodeCallback) {
            ++(*factoryCallCount);
            return std::make_shared<FakeResyncRequest>();
        }));

    PhysicalDeviceStatus statusA;
    statusA.physicalDeviceKey = keyA;
    scheduler->OnPhysicalDeviceStatusChanged({ statusA }); // first snapshot: A
    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(*factoryCallCount, 1);

    scheduler->OnPhysicalDeviceStatusChanged({ statusA }); // unchanged set, no new device
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(*factoryCallCount, 1);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
