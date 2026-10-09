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

#ifndef FUZZ_SOFT_BUS_COORDINATOR_ADAPTER_H
#define FUZZ_SOFT_BUS_COORDINATOR_ADAPTER_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "service_common.h"
#include "soft_bus_coordinator_adapter.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Deterministic coordinator adapter for fuzzing: RequestResource always mirrors the product impl
// (currently unconditional grant), subscriptions are plain map bookkeeping unregistered on
// cleanup, and connection bookkeeping stays synchronous (no resident-thread posting).
class FuzzSoftBusCoordinatorAdapter final : public std::enable_shared_from_this<FuzzSoftBusCoordinatorAdapter>,
                                            public ISoftBusCoordinatorAdapter {
public:
    FuzzSoftBusCoordinatorAdapter() = default;
    ~FuzzSoftBusCoordinatorAdapter() override = default;

    bool Initialize() override
    {
        return true;
    }

    void RequestResource(const std::string &connectionName, const std::string &networkId, ConnectionMode connectionMode,
        ConnectDecisionCallback &&callback) override
    {
        (void)connectionName;
        (void)networkId;
        (void)connectionMode;
        if (callback != nullptr) {
            callback(true);
        }
    }

    void ReleaseResource(const std::string &connectionName) override
    {
        (void)connectionName;
    }

    std::unique_ptr<Subscription> RegisterDisconnectRequestedCallback(DisconnectRequestedCallback &&callback) override
    {
        if (callback == nullptr) {
            return nullptr;
        }
        SubscribeId subscribeId = nextSubscribeId_++;
        disconnectRequestedSubscribers_[subscribeId] = std::move(callback);
        return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscribeId]() {
            auto self = weakSelf.lock();
            if (self != nullptr) {
                self->disconnectRequestedSubscribers_.erase(subscribeId);
            }
        });
    }

    void AddConnection(const std::string &connectionName, const std::string &networkId) override
    {
        (void)connectionName;
        (void)networkId;
    }

    void RemoveConnection(const std::string &connectionName) override
    {
        (void)connectionName;
    }

private:
    uint64_t nextSubscribeId_ = 1;
    std::map<SubscribeId, DisconnectRequestedCallback> disconnectRequestedSubscribers_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // FUZZ_SOFT_BUS_COORDINATOR_ADAPTER_H
