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

#include "mock_guard.h"

#include "cda_attributes.h"
#include "service_common.h"
#include "subscription.h"
#include "synced_peer_registry.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint64_t SEVEN_DAYS_MS = 7ULL * 24 * 60 * 60 * 1000;
constexpr uint64_t SIX_DAYS_MS = 6ULL * 24 * 60 * 60 * 1000;
// MAX_SYNCED_PEERS in synced_peer_registry.cpp
constexpr size_t MAX_SYNCED_PEERS = 50;

EventData BuildPeerSyncedData(DeviceIdType idType, const std::string &deviceId)
{
    Attributes event;
    event.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, deviceId);
    event.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(idType));
    return event.Serialize();
}

PhysicalDeviceKey BuildKey(const std::string &deviceId)
{
    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = deviceId;
    return key;
}

class SyncedPeerRegistryTest : public testing::Test {
public:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }

protected:
    // Captures the handler the registry registers on the event bus, so tests can
    // simulate a peer pull by invoking it directly.
    void CaptureSubscription(MockGuard &guard)
    {
        ON_CALL(guard.GetEventBus(), Subscribe(_, _))
            .WillByDefault(Invoke([this](EventType, EventDataHandler &&handler) {
                eventHandler_ = std::move(handler);
                return std::make_shared<Subscription>([]() {});
            }));
    }

    EventDataHandler eventHandler_;
};

HWTEST_F(SyncedPeerRegistryTest, Start_001, TestSize.Level0)
{
    MockGuard guard;
    CaptureSubscription(guard);

    SyncedPeerRegistry registry;
    EXPECT_TRUE(registry.Start());
    EXPECT_NE(eventHandler_, nullptr);
}

HWTEST_F(SyncedPeerRegistryTest, Start_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetEventBus(), Subscribe(_, _)).WillByDefault(Return(nullptr));

    SyncedPeerRegistry registry;
    EXPECT_FALSE(registry.Start());
}

HWTEST_F(SyncedPeerRegistryTest, IsRecentlySynced_001, TestSize.Level0)
{
    MockGuard guard;

    SyncedPeerRegistry registry;
    EXPECT_FALSE(registry.IsRecentlySynced(BuildKey("dev_unknown")));
}

HWTEST_F(SyncedPeerRegistryTest, HandlePeerSynced_001, TestSize.Level0)
{
    MockGuard guard;
    guard.GetTimeKeeper().SetSteadyTime(1000);
    CaptureSubscription(guard);

    SyncedPeerRegistry registry;
    ASSERT_TRUE(registry.Start());

    eventHandler_(BuildPeerSyncedData(DeviceIdType::UNIFIED_DEVICE_ID, "dev_A"));
    EXPECT_TRUE(registry.IsRecentlySynced(BuildKey("dev_A")));
    EXPECT_FALSE(registry.IsRecentlySynced(BuildKey("dev_B")));
}

HWTEST_F(SyncedPeerRegistryTest, HandlePeerSynced_002, TestSize.Level0)
{
    MockGuard guard;
    guard.GetTimeKeeper().SetSteadyTime(1000);
    CaptureSubscription(guard);

    SyncedPeerRegistry registry;
    ASSERT_TRUE(registry.Start());

    // Malformed payloads (empty, garbage, truncated attributes) must be ignored.
    eventHandler_(EventData {});
    eventHandler_(EventData { 0x01, 0x02, 0x03, 0xff });
    EXPECT_FALSE(registry.IsRecentlySynced(BuildKey("dev_A")));
}

HWTEST_F(SyncedPeerRegistryTest, HandlePeerSynced_003, TestSize.Level0)
{
    MockGuard guard;
    guard.GetTimeKeeper().SetSteadyTime(1000);
    CaptureSubscription(guard);

    SyncedPeerRegistry registry;
    ASSERT_TRUE(registry.Start());

    // The physical key ignores deviceUserId: a second pull under a different user
    // refreshes the same entry instead of creating a new one.
    eventHandler_(BuildPeerSyncedData(DeviceIdType::UNIFIED_DEVICE_ID, "dev_A"));
    guard.GetTimeKeeper().AdvanceSteadyTime(SIX_DAYS_MS);
    eventHandler_(BuildPeerSyncedData(DeviceIdType::UNIFIED_DEVICE_ID, "dev_A"));
    EXPECT_TRUE(registry.IsRecentlySynced(BuildKey("dev_A")));
}

HWTEST_F(SyncedPeerRegistryTest, Ttl_001, TestSize.Level0)
{
    MockGuard guard;
    guard.GetTimeKeeper().SetSteadyTime(1000);
    CaptureSubscription(guard);

    SyncedPeerRegistry registry;
    ASSERT_TRUE(registry.Start());

    eventHandler_(BuildPeerSyncedData(DeviceIdType::UNIFIED_DEVICE_ID, "dev_A"));
    guard.GetTimeKeeper().AdvanceSteadyTime(SIX_DAYS_MS);
    EXPECT_TRUE(registry.IsRecentlySynced(BuildKey("dev_A")));

    guard.GetTimeKeeper().AdvanceSteadyTime(SEVEN_DAYS_MS);
    EXPECT_FALSE(registry.IsRecentlySynced(BuildKey("dev_A")));
}

HWTEST_F(SyncedPeerRegistryTest, Ttl_002, TestSize.Level0)
{
    MockGuard guard;
    guard.GetTimeKeeper().SetSteadyTime(1000);
    CaptureSubscription(guard);

    SyncedPeerRegistry registry;
    ASSERT_TRUE(registry.Start());

    eventHandler_(BuildPeerSyncedData(DeviceIdType::UNIFIED_DEVICE_ID, "dev_A"));
    // A fresh pull within the TTL window restarts the clock.
    guard.GetTimeKeeper().AdvanceSteadyTime(SIX_DAYS_MS);
    eventHandler_(BuildPeerSyncedData(DeviceIdType::UNIFIED_DEVICE_ID, "dev_A"));
    guard.GetTimeKeeper().AdvanceSteadyTime(SIX_DAYS_MS);
    EXPECT_TRUE(registry.IsRecentlySynced(BuildKey("dev_A")));

    guard.GetTimeKeeper().AdvanceSteadyTime(SIX_DAYS_MS);
    EXPECT_FALSE(registry.IsRecentlySynced(BuildKey("dev_A")));
}

HWTEST_F(SyncedPeerRegistryTest, Eviction_001, TestSize.Level0)
{
    MockGuard guard;
    guard.GetTimeKeeper().SetSteadyTime(1000);
    CaptureSubscription(guard);

    SyncedPeerRegistry registry;
    ASSERT_TRUE(registry.Start());

    // Fill the list; each insert advances the clock so recency order is deterministic.
    for (size_t i = 0; i < MAX_SYNCED_PEERS; ++i) {
        eventHandler_(BuildPeerSyncedData(DeviceIdType::UNIFIED_DEVICE_ID, "dev_" + std::to_string(i)));
        guard.GetTimeKeeper().AdvanceSteadyTime(1000);
        EXPECT_TRUE(registry.IsRecentlySynced(BuildKey("dev_" + std::to_string(i))));
    }

    // One more peer evicts the least recently synced entry.
    eventHandler_(BuildPeerSyncedData(DeviceIdType::UNIFIED_DEVICE_ID, "dev_new"));
    EXPECT_FALSE(registry.IsRecentlySynced(BuildKey("dev_0")));
    EXPECT_TRUE(registry.IsRecentlySynced(BuildKey("dev_1")));
    EXPECT_TRUE(registry.IsRecentlySynced(BuildKey("dev_new")));
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
