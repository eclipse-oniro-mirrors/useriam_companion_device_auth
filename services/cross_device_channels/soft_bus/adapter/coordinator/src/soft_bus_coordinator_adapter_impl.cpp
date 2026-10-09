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

#include "soft_bus_coordinator_adapter_impl.h"

#include <algorithm>
#include <cinttypes>
#include <utility>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_safe_arithmetic.h"

#include "adapter_manager.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "soft_bus_channel_common.h"
#include "subscription.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_SOFT_BUS_COORDINATOR_ADAPTER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<SoftBusCoordinatorAdapterImpl> SoftBusCoordinatorAdapterImpl::Create()
{
    auto adapter = std::shared_ptr<SoftBusCoordinatorAdapterImpl>(new (std::nothrow) SoftBusCoordinatorAdapterImpl());
    ENSURE_OR_RETURN_VAL(adapter != nullptr, nullptr);
    if (!adapter->Initialize()) {
        IAM_LOGE("Failed to initialize SoftBusCoordinatorAdapterImpl");
        return nullptr;
    }
    return adapter;
}

bool SoftBusCoordinatorAdapterImpl::Initialize()
{
    return true;
}

void SoftBusCoordinatorAdapterImpl::RequestResource(const std::string &connectionName, const std::string &networkId,
    ConnectionMode connectionMode, ConnectDecisionCallback &&callback)
{
    IAM_LOGI("request resource: %{public}s, networkId=%{public}s, connectionMode=%{public}d", connectionName.c_str(),
        GET_MASKED_STR_CSTR(networkId), static_cast<int32_t>(connectionMode));
    ENSURE_OR_RETURN(callback != nullptr);
    SweepTimedOutPendingApplies();
    if (resources_.find(networkId) != resources_.end()) {
        JoinHeldResource(connectionName, networkId, std::move(callback));
        return;
    }

    auto [it, inserted] = pendingApplies_.try_emplace(networkId);
    PendingApplyEntry &apply = it->second;
    apply.waiters.push_back(WaiterEntry { connectionName, std::move(callback) });
    if (!inserted) {
        JoinPendingApply(connectionName, networkId, connectionMode, apply);
        return;
    }
    SubmitPendingApply(connectionName, networkId, connectionMode, apply);
}

void SoftBusCoordinatorAdapterImpl::JoinHeldResource(const std::string &connectionName, const std::string &networkId,
    ConnectDecisionCallback &&callback)
{
    IAM_LOGI("resource already held, ride: %{public}s, networkId=%{public}s", connectionName.c_str(),
        GET_MASKED_STR_CSTR(networkId));
    resources_[networkId].push_back(connectionName);
    TaskRunnerManager::GetInstance().PostTaskOnResident([callback = std::move(callback)]() { callback(true); });
}

void SoftBusCoordinatorAdapterImpl::JoinPendingApply(const std::string &connectionName, const std::string &networkId,
    ConnectionMode connectionMode, PendingApplyEntry &apply)
{
    if (connectionMode == ConnectionMode::FOREGROUND && apply.submittedMode == ConnectionMode::BACKGROUND &&
        !apply.pendingForegroundEscalation) {
        apply.pendingForegroundEscalation = true;
        IAM_LOGI("foreground joins pending background apply, re-apply as foreground on reject: %{public}s, "
                 "networkId=%{public}s",
            connectionName.c_str(), GET_MASKED_STR_CSTR(networkId));
        return;
    }
    IAM_LOGI("apply already pending, join it: %{public}s, networkId=%{public}s, waiters=%{public}zu",
        connectionName.c_str(), GET_MASKED_STR_CSTR(networkId), apply.waiters.size());
}

void SoftBusCoordinatorAdapterImpl::SubmitPendingApply(const std::string &connectionName, const std::string &networkId,
    ConnectionMode connectionMode, PendingApplyEntry &apply)
{
    apply.applyId = GetMiscManager().GetNextGlobalId();
    auto submitTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    if (!submitTimeMs.has_value()) {
        IAM_LOGE("clock unavailable, deny apply: %{public}s, networkId=%{public}s", connectionName.c_str(),
            GET_MASKED_STR_CSTR(networkId));
        HandleApplyResourceResult(apply.applyId, networkId, false);
        return;
    }
    apply.submittedMode = connectionMode;
    apply.submitTimeMs = submitTimeMs.value();
    if (!ApplyResource(apply.applyId, networkId, connectionMode)) {
        IAM_LOGE("apply resource failed, deny: %{public}s, networkId=%{public}s", connectionName.c_str(),
            GET_MASKED_STR_CSTR(networkId));
        HandleApplyResourceResult(apply.applyId, networkId, false);
    }
}

void SoftBusCoordinatorAdapterImpl::SweepTimedOutPendingApplies()
{
    auto now = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(now.has_value());

    std::vector<std::string> expiredApplies;
    for (const auto &pair : pendingApplies_) {
        auto ageMs = SafeSub(now.value(), pair.second.submitTimeMs);
        if (!ageMs.has_value() || ageMs.value() >= PENDING_ARBITRATION_TIMEOUT_MS) {
            IAM_LOGE("pending apply outlived the arbitration window, settle: %{public}s",
                GET_MASKED_STR_CSTR(pair.first));
            expiredApplies.push_back(pair.first);
        }
    }

    for (const auto &networkId : expiredApplies) {
        auto it = pendingApplies_.find(networkId);
        if (it == pendingApplies_.end()) {
            continue;
        }
        it->second.pendingForegroundEscalation = false;
        HandleApplyResourceResult(it->second.applyId, networkId, false);
    }
}

bool SoftBusCoordinatorAdapterImpl::ApplyResource(uint64_t applyId, const std::string &networkId,
    ConnectionMode connectionMode)
{
    IAM_LOGI("resource granted by default: applyId=%{public}" PRIu64
             ", networkId=%{public}s, connectionMode=%{public}d",
        applyId, GET_MASKED_STR_CSTR(networkId), static_cast<int32_t>(connectionMode));
    PostApplyResourceResult(applyId, networkId, true);
    return true;
}

void SoftBusCoordinatorAdapterImpl::PostApplyResourceResult(uint64_t applyId, const std::string &networkId,
    bool allowed)
{
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), applyId, networkId, allowed]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->HandleApplyResourceResult(applyId, networkId, allowed);
    });
}

void SoftBusCoordinatorAdapterImpl::HandleApplyResourceResult(uint64_t applyId, const std::string &networkId,
    bool allowed)
{
    auto it = pendingApplies_.find(networkId);
    bool isStale = (it == pendingApplies_.end()) || (it->second.applyId != applyId);
    if (isStale) {
        HandleStaleApplyResult(applyId, networkId, allowed);
        return;
    }

    PendingApplyEntry &apply = it->second;
    if (!allowed && apply.pendingForegroundEscalation) {
        ReapplyAsForeground(networkId, apply);
        return;
    }
    CompletePendingApply(it, networkId, applyId, allowed);
}

void SoftBusCoordinatorAdapterImpl::HandleStaleApplyResult(uint64_t applyId, const std::string &networkId, bool allowed)
{
    IAM_LOGW("apply result stale, drop: applyId=%{public}" PRIu64 ", networkId=%{public}s, allowed=%{public}d", applyId,
        GET_MASKED_STR_CSTR(networkId), static_cast<int32_t>(allowed));
    if (!allowed) {
        return;
    }
    const bool isNewResource = resources_.try_emplace(networkId).second;
    if (!isNewResource) {
        IAM_LOGI("stale grant dropped, networkId currently held: %{public}s", GET_MASKED_STR_CSTR(networkId));
        return;
    }
    PostDeferredResourceRelease(networkId);
}

void SoftBusCoordinatorAdapterImpl::PostDeferredResourceRelease(const std::string &networkId)
{
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), networkId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        auto recordIt = self->resources_.find(networkId);
        if (recordIt == self->resources_.end() || !recordIt->second.empty()) {
            IAM_LOGI("resource re-held or already released, skip: networkId=%{public}s",
                GET_MASKED_STR_CSTR(networkId));
            return;
        }
        self->resources_.erase(recordIt);
        self->OnResourceReleased(networkId);
    });
}

void SoftBusCoordinatorAdapterImpl::ReapplyAsForeground(const std::string &networkId, PendingApplyEntry &apply)
{
    IAM_LOGW("background apply rejected with foreground waiter, re-apply as foreground: networkId=%{public}s",
        GET_MASKED_STR_CSTR(networkId));
    auto reapplyTimeMs = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(reapplyTimeMs.has_value());
    apply.pendingForegroundEscalation = false;
    apply.submittedMode = ConnectionMode::FOREGROUND;
    apply.applyId = GetMiscManager().GetNextGlobalId();
    uint64_t reapplyId = apply.applyId;
    apply.submitTimeMs = reapplyTimeMs.value();
    TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), networkId, reapplyId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        auto reapplyIt = self->pendingApplies_.find(networkId);
        if (reapplyIt == self->pendingApplies_.end() || reapplyIt->second.applyId != reapplyId) {
            IAM_LOGI("apply settled or superseded before foreground re-apply, skip: networkId=%{public}s",
                GET_MASKED_STR_CSTR(networkId));
            return;
        }
        if (!self->ApplyResource(reapplyId, networkId, ConnectionMode::FOREGROUND)) {
            self->HandleApplyResourceResult(reapplyId, networkId, false);
        }
    });
}

void SoftBusCoordinatorAdapterImpl::CompletePendingApply(std::map<std::string, PendingApplyEntry>::iterator it,
    const std::string &networkId, uint64_t applyId, bool allowed)
{
    std::vector<WaiterEntry> waiters = std::move(it->second.waiters);
    IAM_LOGI("apply settled: applyId=%{public}" PRIu64
             ", networkId=%{public}s, allowed=%{public}d, waiters=%{public}zu",
        applyId, GET_MASKED_STR_CSTR(networkId), static_cast<int32_t>(allowed), waiters.size());
    pendingApplies_.erase(it);
    if (allowed) {
        auto &names = resources_[networkId];
        for (const auto &waiter : waiters) {
            names.push_back(waiter.connectionName);
        }
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident([waiters = std::move(waiters), allowed]() {
        for (const auto &waiter : waiters) {
            ENSURE_OR_CONTINUE(waiter.callback != nullptr);
            waiter.callback(allowed);
        }
    });
}

void SoftBusCoordinatorAdapterImpl::OnResourceReleased(const std::string &networkId)
{
    IAM_LOGI("resource released by default: networkId=%{public}s", GET_MASKED_STR_CSTR(networkId));
}

std::unique_ptr<Subscription> SoftBusCoordinatorAdapterImpl::RegisterDisconnectRequestedCallback(
    DisconnectRequestedCallback &&callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);
    SubscribeId subscribeId = GetMiscManager().GetNextGlobalId();
    disconnectRequestedSubscribers_[subscribeId] = std::move(callback);

    IAM_LOGD("disconnect requested subscription added: 0x%{public}016" PRIX64 "", subscribeId);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscribeId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnregisterDisconnectRequestedCallback(subscribeId);
    });
}

void SoftBusCoordinatorAdapterImpl::UnregisterDisconnectRequestedCallback(const SubscribeId &subscribeId)
{
    disconnectRequestedSubscribers_.erase(subscribeId);
    IAM_LOGD("disconnect requested subscription removed: 0x%{public}016" PRIX64 "", subscribeId);
}

void SoftBusCoordinatorAdapterImpl::AddConnection(const std::string &connectionName, const std::string &networkId)
{
    auto it = std::find_if(activeConnections_.begin(), activeConnections_.end(),
        [&connectionName](const ConnectionEntry &entry) { return entry.connectionName == connectionName; });
    if (it != activeConnections_.end()) {
        IAM_LOGE("connection already exists: %{public}s, networkId=%{public}s, ignore add", connectionName.c_str(),
            GET_MASKED_STR_CSTR(it->networkId));
        return;
    }

    bool isFirstConnection = !HasActiveConnection(networkId);
    activeConnections_.push_back({ connectionName, networkId });
    if (isFirstConnection) {
        TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), networkId]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnFirstConnectionAdded(networkId);
        });
    }
}

void SoftBusCoordinatorAdapterImpl::RemoveConnection(const std::string &connectionName)
{
    auto it = std::find_if(activeConnections_.begin(), activeConnections_.end(),
        [&connectionName](const ConnectionEntry &entry) { return entry.connectionName == connectionName; });
    if (it == activeConnections_.end()) {
        IAM_LOGI("connection not registered, ignore remove: %{public}s", connectionName.c_str());
        return;
    }

    std::string networkId = it->networkId;
    activeConnections_.erase(it);

    if (HasActiveConnection(networkId)) {
        IAM_LOGI("connection removed but networkId still occupied: %{public}s, networkId=%{public}s",
            connectionName.c_str(), GET_MASKED_STR_CSTR(networkId));
        return;
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident([weakSelf = weak_from_this(), networkId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnLastConnectionRemoved(networkId);
    });
}

void SoftBusCoordinatorAdapterImpl::ReleaseResource(const std::string &connectionName)
{
    for (auto it = resources_.begin(); it != resources_.end(); ++it) {
        auto &names = it->second;
        auto nameIt = std::find(names.begin(), names.end(), connectionName);
        if (nameIt == names.end()) {
            continue;
        }
        names.erase(nameIt);
        if (!names.empty()) {
            IAM_LOGI("resource still held by %{public}zu connections after release: %{public}s, networkId=%{public}s",
                names.size(), connectionName.c_str(), GET_MASKED_STR_CSTR(it->first));
            return;
        }

        std::string networkId = it->first;
        PostDeferredResourceRelease(networkId);
        return;
    }

    IAM_LOGI("connection holds no resource, ignore release: %{public}s", connectionName.c_str());
}

std::vector<std::string> SoftBusCoordinatorAdapterImpl::GetActiveConnectionNetworkIds() const
{
    std::vector<std::string> networkIds;
    for (const auto &entry : activeConnections_) {
        if (std::find(networkIds.begin(), networkIds.end(), entry.networkId) == networkIds.end()) {
            networkIds.push_back(entry.networkId);
        }
    }
    return networkIds;
}

void SoftBusCoordinatorAdapterImpl::HandleDisconnectRequested(const std::string &networkId)
{
    std::vector<DisconnectRequestedCallback> callbacks;
    for (const auto &entry : disconnectRequestedSubscribers_) {
        callbacks.emplace_back(entry.second);
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks), networkId]() {
        for (const auto &callback : callbacks) {
            ENSURE_OR_CONTINUE(callback != nullptr);
            callback(networkId);
        }
    });
}

void SoftBusCoordinatorAdapterImpl::HandleServiceReady()
{
    IAM_LOGI("coordinator service ready");
}

void SoftBusCoordinatorAdapterImpl::HandleServiceUnavailable()
{
    std::vector<ConnectDecisionCallback> callbacks;
    for (auto &entry : pendingApplies_) {
        for (auto &waiter : entry.second.waiters) {
            callbacks.push_back(std::move(waiter.callback));
        }
    }
    pendingApplies_.clear();
    IAM_LOGW("coordinator service unavailable, settle %{public}zu applies", callbacks.size());
    TaskRunnerManager::GetInstance().PostTaskOnResident([callbacks = std::move(callbacks)]() {
        for (const auto &callback : callbacks) {
            ENSURE_OR_CONTINUE(callback != nullptr);
            callback(false);
        }
    });
}

void SoftBusCoordinatorAdapterImpl::OnFirstConnectionAdded(const std::string &networkId)
{
    IAM_LOGI("first connection added, networkId=%{public}s", GET_MASKED_STR_CSTR(networkId));
}

void SoftBusCoordinatorAdapterImpl::OnLastConnectionRemoved(const std::string &networkId)
{
    IAM_LOGI("last connection removed, networkId=%{public}s", GET_MASKED_STR_CSTR(networkId));
}

bool SoftBusCoordinatorAdapterImpl::HasActiveConnection(const std::string &networkId) const
{
    return std::any_of(activeConnections_.begin(), activeConnections_.end(),
        [&networkId](const ConnectionEntry &entry) { return entry.networkId == networkId; });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
