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

#ifndef COMPANION_DEVICE_AUTH_SOFT_BUS_COORDINATOR_ADAPTER_IMPL_H
#define COMPANION_DEVICE_AUTH_SOFT_BUS_COORDINATOR_ADAPTER_IMPL_H

#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "soft_bus_coordinator_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SoftBusCoordinatorAdapterImpl : public std::enable_shared_from_this<SoftBusCoordinatorAdapterImpl>,
                                      public ISoftBusCoordinatorAdapter {
public:
    static std::shared_ptr<SoftBusCoordinatorAdapterImpl> Create();

    ~SoftBusCoordinatorAdapterImpl() override = default;

    void RequestResource(const std::string &connectionName, const std::string &networkId, ConnectionMode connectionMode,
        ConnectDecisionCallback &&callback) override;
    void ReleaseResource(const std::string &connectionName) override;
    std::unique_ptr<Subscription> RegisterDisconnectRequestedCallback(DisconnectRequestedCallback &&callback) override;
    void AddConnection(const std::string &connectionName, const std::string &networkId) override;
    void RemoveConnection(const std::string &connectionName) override;
    void HandleDisconnectRequested(const std::string &networkId);
    void PostApplyResourceResult(uint64_t applyId, const std::string &networkId, bool allowed);

protected:
    SoftBusCoordinatorAdapterImpl() = default;

    bool Initialize() override;

    virtual void HandleServiceReady();
    virtual void HandleServiceUnavailable();
    virtual bool ApplyResource(uint64_t applyId, const std::string &networkId, ConnectionMode connectionMode);
    virtual void OnResourceReleased(const std::string &networkId);
    std::vector<std::string> GetActiveConnectionNetworkIds() const;
    virtual void OnFirstConnectionAdded(const std::string &networkId);
    virtual void OnLastConnectionRemoved(const std::string &networkId);

private:
    struct WaiterEntry {
        std::string connectionName;
        ConnectDecisionCallback callback;
    };

    struct PendingApplyEntry {
        uint64_t applyId { 0 };
        ConnectionMode submittedMode { ConnectionMode::BACKGROUND };
        bool pendingForegroundEscalation { false };
        uint64_t submitTimeMs { 0 };
        std::vector<WaiterEntry> waiters;
    };

    void UnregisterDisconnectRequestedCallback(const SubscribeId &subscribeId);
    void SweepTimedOutPendingApplies();
    void PostDeferredResourceRelease(const std::string &networkId);
    void JoinHeldResource(const std::string &connectionName, const std::string &networkId,
        ConnectDecisionCallback &&callback);
    void JoinPendingApply(const std::string &connectionName, const std::string &networkId,
        ConnectionMode connectionMode, PendingApplyEntry &apply);
    void SubmitPendingApply(const std::string &connectionName, const std::string &networkId,
        ConnectionMode connectionMode, PendingApplyEntry &apply);
    void HandleApplyResourceResult(uint64_t applyId, const std::string &networkId, bool allowed);
    void HandleStaleApplyResult(uint64_t applyId, const std::string &networkId, bool allowed);
    void ReapplyAsForeground(const std::string &networkId, PendingApplyEntry &apply);
    void CompletePendingApply(std::map<std::string, PendingApplyEntry>::iterator it, const std::string &networkId,
        uint64_t applyId, bool allowed);
    bool HasActiveConnection(const std::string &networkId) const;

    struct ConnectionEntry {
        std::string connectionName;
        std::string networkId;
    };

    std::map<SubscribeId, DisconnectRequestedCallback> disconnectRequestedSubscribers_;
    std::deque<ConnectionEntry> activeConnections_;
    std::map<std::string, PendingApplyEntry> pendingApplies_;
    std::map<std::string, std::vector<std::string>> resources_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SOFT_BUS_COORDINATOR_ADAPTER_IMPL_H
