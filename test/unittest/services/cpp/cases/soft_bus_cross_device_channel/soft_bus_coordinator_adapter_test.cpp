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

#include <string>
#include <vector>

#include "mock_guard.h"

#include "soft_bus_channel_common.h"
#include "soft_bus_coordinator_adapter_impl.h"
#include "subscription.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr const char *TEST_CONNECTION_NAME = "test-connection";
constexpr const char *TEST_OTHER_CONNECTION_NAME = "other-connection";
constexpr const char *TEST_THIRD_CONNECTION_NAME = "third-connection";
constexpr const char *TEST_UNKNOWN_CONNECTION_NAME = "unknown-connection";
constexpr const char *TEST_NETWORK_ID = "test-network-id";
constexpr const char *TEST_OTHER_NETWORK_ID = "other-network-id";

class SoftBusCoordinatorAdapterTest : public Test {
protected:
    void SetUp() override
    {
        // Cleanup closures hold a weak ref, so the adapter must be shared-owned.
        adapter_ = SoftBusCoordinatorAdapterImpl::Create();
        ASSERT_NE(adapter_, nullptr);
    }

    std::shared_ptr<SoftBusCoordinatorAdapterImpl> adapter_;
};

class SyncDenyAdapter final : public SoftBusCoordinatorAdapterImpl {
public:
    bool ApplyResource(uint64_t applyId, const std::string &networkId, ConnectionMode connectionMode) override
    {
        ++applyCount;
        return false;
    }

    int applyCount = 0;
};

// Records every apply submission and never settles on its own, so tests drive decisions
// through HandleApplyResourceResult exactly when they choose to.
class ApplyModeSpyAdapter final : public SoftBusCoordinatorAdapterImpl {
public:
    bool ApplyResource(uint64_t applyId, const std::string &networkId, ConnectionMode connectionMode) override
    {
        appliedModes.push_back(connectionMode);
        return submitResult;
    }

    void OnResourceReleased(const std::string &networkId) override
    {
        releasedResources.push_back(networkId);
    }

    std::vector<std::string> releasedResources;
    std::vector<ConnectionMode> appliedModes;
    bool submitResult = true;
};

// Records the resource hooks so tests can assert what the ext would have been told.
class ResourceHookSpyAdapter final : public SoftBusCoordinatorAdapterImpl {
public:
    void OnFirstConnectionAdded(const std::string &networkId) override
    {
        acquired.push_back(networkId);
    }

    void OnLastConnectionRemoved(const std::string &networkId) override
    {
        released.push_back(networkId);
    }

    std::vector<std::string> acquired;
    std::vector<std::string> released;
};

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_001, TestSize.Level0)
{
    MockGuard guard;

    bool canConnect = false;
    adapter_->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&canConnect](bool result) { canConnect = result; });
    // The decision is posted to the resident queue, not delivered inline.
    EXPECT_FALSE(canConnect);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(canConnect);
    EXPECT_TRUE(adapter_->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_002, TestSize.Level0)
{
    MockGuard guard;

    bool canConnect = false;
    adapter_->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&canConnect](bool result) { canConnect = result; });
    EXPECT_FALSE(canConnect);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(canConnect);
    EXPECT_TRUE(adapter_->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_003, TestSize.Level0)
{
    MockGuard guard;

    // A null callback is rejected without booking a pending apply.
    adapter_->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND, nullptr);
    EXPECT_TRUE(adapter_->pendingApplies_.empty());
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(adapter_->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_004, TestSize.Level0)
{
    MockGuard guard;

    // Seed a still-pending apply, as the ext arbitration path would leave behind.
    bool seededCanConnect = false;
    adapter_->pendingApplies_[TEST_NETWORK_ID].waiters.push_back(SoftBusCoordinatorAdapterImpl::WaiterEntry {
        TEST_CONNECTION_NAME, [&seededCanConnect](bool result) { seededCanConnect = result; } });

    // A second connection on the still-pending networkId joins the same apply instead of being
    // dropped: one resource decision, every waiter settled by it.
    bool newCanConnect = false;
    adapter_->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&newCanConnect](bool result) { newCanConnect = result; });
    EXPECT_FALSE(newCanConnect);
    ASSERT_EQ(adapter_->pendingApplies_.size(), 1);
    ASSERT_EQ(adapter_->pendingApplies_.at(TEST_NETWORK_ID).waiters.size(), 2);

    adapter_->HandleApplyResourceResult(adapter_->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(seededCanConnect);
    EXPECT_TRUE(newCanConnect);
    EXPECT_TRUE(adapter_->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_005, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<SyncDenyAdapter>();

    // A synchronous ApplyResource failure settles the apply inline as denied.
    bool canConnect = true;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&canConnect](bool result) { canConnect = result; });
    EXPECT_EQ(adapter->applyCount, 1);
    EXPECT_TRUE(adapter->pendingApplies_.empty());

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_FALSE(canConnect);
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_006, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<SyncDenyAdapter>();

    // The device already holds a granted resource: a new connection on it rides the grant and is
    // allowed straight away, without a second apply the ext would have to arbitrate again.
    adapter->resources_[TEST_NETWORK_ID] = { TEST_CONNECTION_NAME };

    bool canConnect = false;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&canConnect](bool result) { canConnect = result; });
    EXPECT_EQ(adapter->applyCount, 0);
    EXPECT_TRUE(adapter->pendingApplies_.empty());
    // The rider is recorded on the holding list, so its later release is accounted for.
    ASSERT_EQ(adapter->resources_.at(TEST_NETWORK_ID).size(), 2);
    EXPECT_EQ(adapter->resources_.at(TEST_NETWORK_ID).back(), TEST_OTHER_CONNECTION_NAME);

    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(canConnect);
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_007, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    // The first applier is background, so the ext arbitrates background while the apply pends.
    int bgResult = -1;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&bgResult](bool result) { bgResult = static_cast<int>(result); });

    // A foreground waiter joins the pending background apply: its mode must not vanish silently.
    int fgResult = -1;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&fgResult](bool result) { fgResult = static_cast<int>(result); });

    ASSERT_EQ(adapter->appliedModes.size(), 1u);
    EXPECT_EQ(adapter->appliedModes.at(0), ConnectionMode::BACKGROUND);
    EXPECT_TRUE(adapter->pendingApplies_.at(TEST_NETWORK_ID).pendingForegroundEscalation);

    // Background rejected: nobody is settled yet, the apply is re-submitted as foreground once.
    adapter->HandleApplyResourceResult(adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, false);
    EXPECT_EQ(bgResult, -1);
    EXPECT_EQ(fgResult, -1);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    ASSERT_EQ(adapter->appliedModes.size(), 2u);
    EXPECT_EQ(adapter->appliedModes.at(1), ConnectionMode::FOREGROUND);
    ASSERT_EQ(adapter->pendingApplies_.size(), 1u);

    // Foreground approved: every waiter rides the foreground grant.
    adapter->HandleApplyResourceResult(adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(bgResult, 1);
    EXPECT_EQ(fgResult, 1);
    EXPECT_TRUE(adapter->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_008, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    int bgResult = -1;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&bgResult](bool result) { bgResult = static_cast<int>(result); });
    int fgResult = -1;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&fgResult](bool result) { fgResult = static_cast<int>(result); });

    // The escalated foreground apply is rejected too: all waiters are denied, exactly one
    // re-apply happened, and no further escalation loops.
    adapter->HandleApplyResourceResult(adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, false);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    adapter->HandleApplyResourceResult(adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, false);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(bgResult, 0);
    EXPECT_EQ(fgResult, 0);
    EXPECT_EQ(adapter->appliedModes.size(), 2u);
    EXPECT_TRUE(adapter->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_009, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    // Both waiters are foreground: a rejection settles everyone directly, no re-apply.
    int firstResult = -1;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&firstResult](bool result) { firstResult = static_cast<int>(result); });
    int secondResult = -1;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&secondResult](bool result) { secondResult = static_cast<int>(result); });
    EXPECT_FALSE(adapter->pendingApplies_.at(TEST_NETWORK_ID).pendingForegroundEscalation);

    adapter->HandleApplyResourceResult(adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, false);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(firstResult, 0);
    EXPECT_EQ(secondResult, 0);
    EXPECT_EQ(adapter->appliedModes.size(), 1u);
    EXPECT_TRUE(adapter->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_010, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    // A background waiter joining a pending foreground apply neither downgrades it nor arms
    // an escalation: the ext keeps arbitrating the foreground apply.
    int fgResult = -1;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&fgResult](bool result) { fgResult = static_cast<int>(result); });
    int bgResult = -1;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&bgResult](bool result) { bgResult = static_cast<int>(result); });
    EXPECT_FALSE(adapter->pendingApplies_.at(TEST_NETWORK_ID).pendingForegroundEscalation);

    adapter->HandleApplyResourceResult(adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, false);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(fgResult, 0);
    EXPECT_EQ(bgResult, 0);
    EXPECT_EQ(adapter->appliedModes.size(), 1u);
    EXPECT_EQ(adapter->appliedModes.at(0), ConnectionMode::FOREGROUND);
    EXPECT_TRUE(adapter->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_011, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    int bgResult = -1;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&bgResult](bool result) { bgResult = static_cast<int>(result); });
    int fgResult = -1;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&fgResult](bool result) { fgResult = static_cast<int>(result); });

    // The escalated re-apply fails to submit synchronously: the entry is settled as denied
    // instead of being left parked forever.
    adapter->submitResult = false;
    adapter->HandleApplyResourceResult(adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, false);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    ASSERT_EQ(adapter->appliedModes.size(), 2u);
    EXPECT_EQ(adapter->appliedModes.at(1), ConnectionMode::FOREGROUND);
    EXPECT_EQ(bgResult, 0);
    EXPECT_EQ(fgResult, 0);
    EXPECT_TRUE(adapter->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, HandleApplyResourceResult_001, TestSize.Level0)
{
    MockGuard guard;

    bool canConnect = false;
    adapter_->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&canConnect](bool result) { canConnect = result; });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    ASSERT_TRUE(canConnect);

    // Settling an unknown or already-settled apply is dropped, not a crash: the stale deny is
    // ignored and the stale allow only returns the grant through ReleaseResource.
    adapter_->HandleApplyResourceResult(0, TEST_NETWORK_ID, false);
    adapter_->HandleApplyResourceResult(0, TEST_OTHER_NETWORK_ID, true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(canConnect);
}

HWTEST_F(SoftBusCoordinatorAdapterTest, StaleGrant_NewApplyGrantedBeforeRelease, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();
    ASSERT_NE(adapter, nullptr);

    int oldResults = 0;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&oldResults](bool allowed) {
            ++oldResults;
            EXPECT_FALSE(allowed);
        });
    auto oldId = adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId;
    guard.GetTimeKeeper().AdvanceSteadyTime(PENDING_ARBITRATION_TIMEOUT_MS);
    int newResults = 0;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&newResults](bool allowed) {
            ++newResults;
            EXPECT_TRUE(allowed);
        });
    auto newId = adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId;
    ASSERT_NE(oldId, newId);
    adapter->HandleApplyResourceResult(oldId, TEST_NETWORK_ID, false);
    adapter->HandleApplyResourceResult(oldId, TEST_NETWORK_ID, true);
    adapter->HandleApplyResourceResult(newId, TEST_NETWORK_ID, true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(oldResults, 1);
    EXPECT_EQ(newResults, 1);
    EXPECT_TRUE(adapter->releasedResources.empty());
    adapter->ReleaseResource(TEST_OTHER_CONNECTION_NAME);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(adapter->releasedResources, std::vector<std::string> { TEST_NETWORK_ID });
    EXPECT_TRUE(adapter->resources_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, StaleGrant_RepeatedResultReleasedOnce, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();
    ASSERT_NE(adapter, nullptr);

    adapter->HandleApplyResourceResult(0, TEST_NETWORK_ID, false);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(adapter->releasedResources.empty());
    EXPECT_TRUE(adapter->resources_.empty());

    adapter->HandleApplyResourceResult(0, TEST_NETWORK_ID, true);
    adapter->HandleApplyResourceResult(0, TEST_NETWORK_ID, true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(adapter->releasedResources, std::vector<std::string> { TEST_NETWORK_ID });
    EXPECT_TRUE(adapter->resources_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, StaleGrant_NewConnectionRidesBeforeRelease, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();
    ASSERT_NE(adapter, nullptr);

    adapter->HandleApplyResourceResult(0, TEST_NETWORK_ID, true);
    int results = 0;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&results](bool allowed) {
            ++results;
            EXPECT_TRUE(allowed);
        });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(results, 1);
    EXPECT_TRUE(adapter->appliedModes.empty());
    EXPECT_TRUE(adapter->releasedResources.empty());

    adapter->ReleaseResource(TEST_CONNECTION_NAME);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(adapter->releasedResources, std::vector<std::string> { TEST_NETWORK_ID });
    EXPECT_TRUE(adapter->resources_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, HandleServiceUnavailable_001, TestSize.Level0)
{
    MockGuard guard;

    bool firstCanConnect = true;
    bool secondCanConnect = true;
    adapter_->pendingApplies_[TEST_NETWORK_ID].waiters.push_back(SoftBusCoordinatorAdapterImpl::WaiterEntry {
        TEST_CONNECTION_NAME, [&firstCanConnect](bool result) { firstCanConnect = result; } });
    adapter_->pendingApplies_[TEST_OTHER_NETWORK_ID].waiters.push_back(SoftBusCoordinatorAdapterImpl::WaiterEntry {
        TEST_OTHER_CONNECTION_NAME, [&secondCanConnect](bool result) { secondCanConnect = result; } });

    std::vector<std::string> received;
    auto subscription = adapter_->RegisterDisconnectRequestedCallback(
        [&received](const std::string &networkId) { received.push_back(networkId); });
    ASSERT_NE(subscription, nullptr);
    adapter_->AddConnection(TEST_CONNECTION_NAME, TEST_NETWORK_ID);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    // Service death settles every pending apply as denied and leaves subscribers untouched.
    adapter_->HandleServiceUnavailable();
    EXPECT_TRUE(adapter_->pendingApplies_.empty());
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_FALSE(firstCanConnect);
    EXPECT_FALSE(secondCanConnect);
    EXPECT_TRUE(received.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, HandleServiceUnavailable_002, TestSize.Level0)
{
    MockGuard guard;

    // An empty adapter settles nothing and dispatches nothing.
    std::vector<std::string> received;
    auto subscription = adapter_->RegisterDisconnectRequestedCallback(
        [&received](const std::string &networkId) { received.push_back(networkId); });
    ASSERT_NE(subscription, nullptr);

    adapter_->HandleServiceUnavailable();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(received.empty());
    EXPECT_TRUE(adapter_->pendingApplies_.empty());
    EXPECT_TRUE(adapter_->activeConnections_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, HandleServiceUnavailable_003, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    // An armed escalation dies with the service: service death denies every waiter rather
    // than waiting for a re-apply that can never settle.
    int bgResult = -1;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&bgResult](bool result) { bgResult = static_cast<int>(result); });
    int fgResult = -1;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&fgResult](bool result) { fgResult = static_cast<int>(result); });
    ASSERT_TRUE(adapter->pendingApplies_.at(TEST_NETWORK_ID).pendingForegroundEscalation);

    adapter->HandleServiceUnavailable();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(bgResult, 0);
    EXPECT_EQ(fgResult, 0);
    EXPECT_TRUE(adapter->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, HandleServiceUnavailable_004, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    int bgResult = -1;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&bgResult](bool result) { bgResult = static_cast<int>(result); });
    int fgResult = -1;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&fgResult](bool result) { fgResult = static_cast<int>(result); });

    // The rejection arms the foreground re-apply, but the service dies before the posted re-apply
    // runs: the entry is gone, so no orphan apply may reach the ext.
    adapter->HandleApplyResourceResult(adapter->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, false);
    adapter->HandleServiceUnavailable();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    ASSERT_EQ(adapter->appliedModes.size(), 1U);
    EXPECT_EQ(adapter->appliedModes.front(), ConnectionMode::BACKGROUND);
    EXPECT_EQ(bgResult, 0);
    EXPECT_EQ(fgResult, 0);
    EXPECT_TRUE(adapter->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, HandleServiceReady_001, TestSize.Level0)
{
    MockGuard guard;

    // Seed a still-pending apply, as the ext arbitration path would leave behind.
    bool canConnect = false;
    adapter_->pendingApplies_[TEST_NETWORK_ID].waiters.push_back(SoftBusCoordinatorAdapterImpl::WaiterEntry {
        TEST_CONNECTION_NAME, [&canConnect](bool result) { canConnect = result; } });

    std::vector<std::string> received;
    auto subscription = adapter_->RegisterDisconnectRequestedCallback(
        [&received](const std::string &networkId) { received.push_back(networkId); });
    ASSERT_NE(subscription, nullptr);

    // The service becoming (re)ready settles nothing by itself, unlike unavailability: the
    // apply stays pending until its own decision arrives.
    adapter_->HandleServiceReady();
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_FALSE(canConnect);
    ASSERT_EQ(adapter_->pendingApplies_.size(), 1);
    EXPECT_TRUE(received.empty());

    adapter_->HandleApplyResourceResult(adapter_->pendingApplies_.at(TEST_NETWORK_ID).applyId, TEST_NETWORK_ID, true);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_TRUE(canConnect);
    EXPECT_TRUE(adapter_->pendingApplies_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RegisterDisconnectRequestedCallback_001, TestSize.Level0)
{
    MockGuard guard;

    auto subscription = adapter_->RegisterDisconnectRequestedCallback(nullptr);
    EXPECT_EQ(subscription, nullptr);
    EXPECT_TRUE(adapter_->disconnectRequestedSubscribers_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RegisterDisconnectRequestedCallback_002, TestSize.Level0)
{
    MockGuard guard;
    int invokedCount = 0;
    {
        auto subscription =
            adapter_->RegisterDisconnectRequestedCallback([&invokedCount](const std::string &) { ++invokedCount; });
        ASSERT_NE(subscription, nullptr);
        EXPECT_EQ(adapter_->disconnectRequestedSubscribers_.size(), 1);
    }
    // Subscription destruction unregisters the callback.
    EXPECT_TRUE(adapter_->disconnectRequestedSubscribers_.empty());

    adapter_->HandleDisconnectRequested(TEST_NETWORK_ID);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(invokedCount, 0);
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RegisterDisconnectRequestedCallback_003, TestSize.Level0)
{
    MockGuard guard;
    auto subscription = adapter_->RegisterDisconnectRequestedCallback([](const std::string &) {});
    ASSERT_NE(subscription, nullptr);

    subscription->Cancel();
    EXPECT_TRUE(adapter_->disconnectRequestedSubscribers_.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RegisterDisconnectRequestedCallback_004, TestSize.Level0)
{
    MockGuard guard;
    auto localAdapter = SoftBusCoordinatorAdapterImpl::Create();
    ASSERT_NE(localAdapter, nullptr);
    auto subscription = localAdapter->RegisterDisconnectRequestedCallback([](const std::string &) {});
    ASSERT_NE(subscription, nullptr);

    // Cleanup on an expired adapter must be a no-op, not a crash.
    localAdapter.reset();
    subscription.reset();
}

HWTEST_F(SoftBusCoordinatorAdapterTest, AddConnection_001, TestSize.Level0)
{
    MockGuard guard;
    adapter_->AddConnection(TEST_CONNECTION_NAME, TEST_NETWORK_ID);
    ASSERT_EQ(adapter_->activeConnections_.size(), 1);
    TaskRunnerManager::GetInstance().ExecuteAll();

    // A duplicate connectionName is ignored even for a different networkId.
    adapter_->AddConnection(TEST_CONNECTION_NAME, TEST_OTHER_NETWORK_ID);
    EXPECT_EQ(adapter_->activeConnections_.size(), 1);
    EXPECT_EQ(adapter_->activeConnections_.front().networkId, TEST_NETWORK_ID);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusCoordinatorAdapterTest, AddConnection_002, TestSize.Level0)
{
    MockGuard guard;
    adapter_->AddConnection(TEST_CONNECTION_NAME, TEST_NETWORK_ID);
    // A second connection on the same networkId must not re-run the first-connection path.
    adapter_->AddConnection(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID);
    EXPECT_EQ(adapter_->activeConnections_.size(), 2);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RemoveConnection_001, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ResourceHookSpyAdapter>();
    adapter->AddConnection(TEST_CONNECTION_NAME, TEST_NETWORK_ID);
    TaskRunnerManager::GetInstance().ExecuteAll();

    // An unregistered connectionName drops nothing, and the device is still held by the
    // registered connection, so no release reaches the ext either.
    adapter->RemoveConnection(TEST_UNKNOWN_CONNECTION_NAME);
    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_EQ(adapter->activeConnections_.size(), 1);
    EXPECT_EQ(adapter->acquired, std::vector<std::string> { TEST_NETWORK_ID });
    EXPECT_TRUE(adapter->released.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RemoveConnection_002, TestSize.Level0)
{
    MockGuard guard;
    adapter_->AddConnection(TEST_CONNECTION_NAME, TEST_NETWORK_ID);
    adapter_->AddConnection(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID);
    adapter_->AddConnection(TEST_THIRD_CONNECTION_NAME, TEST_OTHER_NETWORK_ID);

    // networkId still holds TEST_OTHER_CONNECTION_NAME, so no last-connection removal runs.
    adapter_->RemoveConnection(TEST_CONNECTION_NAME);
    EXPECT_EQ(adapter_->activeConnections_.size(), 2);
    TaskRunnerManager::GetInstance().ExecuteAll();

    // Dropping the last connection of a networkId runs the removal path.
    adapter_->RemoveConnection(TEST_OTHER_CONNECTION_NAME);
    EXPECT_EQ(adapter_->activeConnections_.size(), 1);
    EXPECT_EQ(adapter_->activeConnections_.front().connectionName, TEST_THIRD_CONNECTION_NAME);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusCoordinatorAdapterTest, RemoveConnection_003, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ResourceHookSpyAdapter>();

    // An unregistered connectionName is a silent no-op: occupancy notifications only describe
    // connections that were actually registered, and grant returns go through ReleaseResource.
    adapter->RemoveConnection(TEST_UNKNOWN_CONNECTION_NAME);

    TaskRunnerManager::GetInstance().ExecuteAll();
    EXPECT_TRUE(adapter->acquired.empty());
    EXPECT_TRUE(adapter->released.empty());
}

HWTEST_F(SoftBusCoordinatorAdapterTest, GetActiveConnectionNetworkIds_001, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_TRUE(adapter_->GetActiveConnectionNetworkIds().empty());

    adapter_->AddConnection(TEST_CONNECTION_NAME, TEST_NETWORK_ID);
    adapter_->AddConnection(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID);
    adapter_->AddConnection(TEST_THIRD_CONNECTION_NAME, TEST_OTHER_NETWORK_ID);
    TaskRunnerManager::GetInstance().ExecuteAll();

    // networkIds are deduplicated per device, in insertion order.
    auto networkIds = adapter_->GetActiveConnectionNetworkIds();
    ASSERT_EQ(networkIds.size(), 2);
    EXPECT_EQ(networkIds.at(0), TEST_NETWORK_ID);
    EXPECT_EQ(networkIds.at(1), TEST_OTHER_NETWORK_ID);

    adapter_->RemoveConnection(TEST_THIRD_CONNECTION_NAME);
    TaskRunnerManager::GetInstance().ExecuteAll();
    networkIds = adapter_->GetActiveConnectionNetworkIds();
    ASSERT_EQ(networkIds.size(), 1);
    EXPECT_EQ(networkIds.front(), TEST_NETWORK_ID);
}

HWTEST_F(SoftBusCoordinatorAdapterTest, HandleDisconnectRequested_001, TestSize.Level0)
{
    MockGuard guard;
    std::vector<std::string> firstReceived;
    std::vector<std::string> secondReceived;
    auto firstSubscription = adapter_->RegisterDisconnectRequestedCallback(
        [&firstReceived](const std::string &networkId) { firstReceived.push_back(networkId); });
    auto secondSubscription = adapter_->RegisterDisconnectRequestedCallback(
        [&secondReceived](const std::string &networkId) { secondReceived.push_back(networkId); });
    ASSERT_NE(firstSubscription, nullptr);
    ASSERT_NE(secondSubscription, nullptr);

    adapter_->HandleDisconnectRequested(TEST_NETWORK_ID);
    // Dispatch is posted to the resident queue, not delivered inline.
    EXPECT_TRUE(firstReceived.empty());
    EXPECT_TRUE(secondReceived.empty());

    TaskRunnerManager::GetInstance().ExecuteAll();
    ASSERT_EQ(firstReceived.size(), 1);
    ASSERT_EQ(secondReceived.size(), 1);
    EXPECT_EQ(firstReceived.front(), TEST_NETWORK_ID);
    EXPECT_EQ(secondReceived.front(), TEST_NETWORK_ID);
}

// A lost arbitration must not stick: joining a stale apply settles it (denies its waiters) and
// submits a fresh apply, instead of piling onto an entry whose arbitration is never coming back.
HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_TimedOutApplySettledAndReapplied, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    int oldWaiterResults = 0;
    bool oldAllowed = true;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&oldWaiterResults, &oldAllowed](bool allowed) {
            ++oldWaiterResults;
            oldAllowed = allowed;
        });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1u, adapter->appliedModes.size());

    // The arbitration callback never arrives; the apply outlives the window.
    guard.GetTimeKeeper().AdvanceSteadyTime(PENDING_ARBITRATION_TIMEOUT_MS);
    bool newAllowed = true;
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&newAllowed](bool allowed) { newAllowed = allowed; });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(1, oldWaiterResults);
    EXPECT_FALSE(oldAllowed);
    EXPECT_EQ(2u, adapter->appliedModes.size());
    EXPECT_FALSE(adapter->pendingApplies_.empty());
}

// Joining a stale escalated apply must settle it, not loop the arbitration into a foreground
// re-apply; the fresh submission carries the new request's own mode.
HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_TimedOutEscalationSettlesWithoutReapply, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    int oldWaiterResults = 0;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&oldWaiterResults](bool allowed) { ++oldWaiterResults; });
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [&oldWaiterResults](bool allowed) { ++oldWaiterResults; });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    EXPECT_EQ(1u, adapter->appliedModes.size());

    guard.GetTimeKeeper().AdvanceSteadyTime(PENDING_ARBITRATION_TIMEOUT_MS);
    adapter->RequestResource(TEST_THIRD_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [](bool allowed) { (void)allowed; });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_EQ(2, oldWaiterResults);
    EXPECT_EQ(2u, adapter->appliedModes.size());
    EXPECT_EQ(std::count(adapter->appliedModes.begin(), adapter->appliedModes.end(), ConnectionMode::FOREGROUND), 0);
}

// A clock rollback (submit time ahead of now) underflows SafeSub; the entry sweep settles the
// stale apply as deny — same settle-on-anomaly semantics as the connection manager sweeps.
HWTEST_F(SoftBusCoordinatorAdapterTest, RequestResource_ClockRollback_SettlesStaleApplyAsDeny, TestSize.Level0)
{
    MockGuard guard;
    auto adapter = std::make_shared<ApplyModeSpyAdapter>();

    guard.GetTimeKeeper().SetSteadyTime(5000);
    bool firstDenied = false;
    adapter->RequestResource(TEST_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::BACKGROUND,
        [&firstDenied](bool allowed) { firstDenied = !allowed; });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    ASSERT_EQ(1u, adapter->appliedModes.size());

    // Simulate a clock rollback: submit time ahead of now -> SafeSub underflows to nullopt.
    guard.GetTimeKeeper().SetSteadyTime(1000);
    adapter->RequestResource(TEST_OTHER_CONNECTION_NAME, TEST_NETWORK_ID, ConnectionMode::FOREGROUND,
        [](bool allowed) { (void)allowed; });
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();

    EXPECT_TRUE(firstDenied);
    EXPECT_EQ(2u, adapter->appliedModes.size());
    EXPECT_EQ(adapter->appliedModes.back(), ConnectionMode::FOREGROUND);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
