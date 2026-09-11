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

#ifndef COMPANION_DEVICE_AUTH_FAKE_CHANNEL_H
#define COMPANION_DEVICE_AUTH_FAKE_CHANNEL_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "cross_device_common.h"
#include "icross_device_channel.h"
#include "subscription.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FakeChannel : public ICrossDeviceChannel {
public:
    FakeChannel() = default;
    ~FakeChannel() override = default;

    bool Start() override
    {
        return true;
    }

    ChannelId GetChannelId() const override
    {
        return ChannelId::SOFTBUS;
    }

    std::optional<PhysicalDeviceKey> GetLocalPhysicalDeviceKey() const override
    {
        PhysicalDeviceKey key;
        key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        key.deviceId = "local-test-device";
        return key;
    }

    SecureProtocolId GetCompanionSecureProtocolId() const override
    {
        return SecureProtocolId::DEFAULT;
    }

    bool RequiresDisconnectNotification() const override
    {
        return false;
    }

    bool GetAuthMaintainActive() const override
    {
        return isAuthMaintainActive_;
    }

    // Test backdoor: set auth maintain active state
    void TestSetAuthMaintainActive(bool active)
    {
        isAuthMaintainActive_ = active;
    }

    std::vector<PhysicalDeviceStatus> GetAllPhysicalDevices() const override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return onlineDevices_;
    }

    void RefreshPhysicalDeviceStatus() override
    {
    }

    // === Connection management ===

    bool OpenConnection(const std::string &connectionName, const PhysicalDeviceKey &) override
    {
        // Defer callback to match real channel async behavior.
        // ConnectionManager adds connection to its map AFTER OpenConnection returns,
        // so synchronous callback would fire before the connection is tracked.
        if (connectionStatusCb_) {
            auto cb = connectionStatusCb_;
            TaskRunnerManager::GetInstance().PostTaskOnResident([cb, connectionName]() {
                if (cb) {
                    cb(connectionName, ConnectionStatus::CONNECTED, "test_connected");
                }
            });
        }
        return true;
    }

    void CloseConnection(const std::string &, const std::string &) override
    {
    }

    void OnRemoteDisconnect(const std::string &connectionName, const std::string &reason) override
    {
        if (connectionStatusCb_) {
            connectionStatusCb_(connectionName, ConnectionStatus::DISCONNECTED, reason);
        }
    }

    // === Message sending (captured to queue) ===

    bool SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sentMessages_[connectionName].push_back(rawMsg);
        return true;
    }

    // === Subscriptions (capture callbacks) ===

    std::unique_ptr<Subscription> SubscribePhysicalDeviceStatus(OnPhysicalDeviceStatusChange &&cb) override
    {
        physicalDeviceStatusCb_ = std::move(cb);
        return std::make_unique<Subscription>([this]() { physicalDeviceStatusCb_ = nullptr; });
    }

    std::unique_ptr<Subscription> SubscribeAuthMaintainActive(OnAuthMaintainActiveChange &&) override
    {
        return std::make_unique<Subscription>([]() {});
    }

    std::unique_ptr<Subscription> SubscribeRawMessage(OnRawMessage &&cb) override
    {
        rawMessageCb_ = std::move(cb);
        return std::make_unique<Subscription>([this]() { rawMessageCb_ = nullptr; });
    }

    std::unique_ptr<Subscription> SubscribeConnectionStatus(OnConnectionStatusChange &&cb) override
    {
        connectionStatusCb_ = std::move(cb);
        return std::make_unique<Subscription>([this]() { connectionStatusCb_ = nullptr; });
    }

    std::unique_ptr<Subscription> SubscribeIncomingConnection(OnIncomingConnection &&cb) override
    {
        incomingConnectionCb_ = std::move(cb);
        return std::make_unique<Subscription>([this]() { incomingConnectionCb_ = nullptr; });
    }

    bool CheckOperationIntent(const DeviceKey &, uint32_t, OnCheckOperationIntentResult &&resultCallback) override
    {
        if (resultCallback) {
            resultCallback(true);
        }
        return true;
    }

    // === Test backdoors ===

    void TestSimulateDeviceOnline(const PhysicalDeviceKey &key)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            PhysicalDeviceStatus status;
            status.physicalDeviceKey = key;
            status.isAuthMaintainActive = true;
            onlineDevices_.push_back(status);
        }
        if (physicalDeviceStatusCb_) {
            PhysicalDeviceStatus status;
            status.physicalDeviceKey = key;
            status.isAuthMaintainActive = true;
            physicalDeviceStatusCb_({ status });
        }
    }

    void TestSimulateIncomingMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg)
    {
        if (rawMessageCb_) {
            rawMessageCb_(connectionName, rawMsg);
        }
    }

    void TestSimulateRemoteDisconnect(const std::string &connectionName, const std::string &reason)
    {
        if (connectionStatusCb_) {
            connectionStatusCb_(connectionName, ConnectionStatus::DISCONNECTED, reason);
        }
    }

    void TestSimulateIncomingConnection(const std::string &connectionName, const PhysicalDeviceKey &remoteKey)
    {
        if (incomingConnectionCb_) {
            incomingConnectionCb_(connectionName, remoteKey);
        }
    }

    // === Test query ===

    std::vector<std::vector<uint8_t>> GetSentMessages(const std::string &connectionName) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sentMessages_.find(connectionName);
        return it != sentMessages_.end() ? it->second : std::vector<std::vector<uint8_t>> {};
    }

    std::vector<std::string> GetAllConnectionNames() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> names;
        names.reserve(sentMessages_.size());
        for (const auto &pair : sentMessages_) {
            names.push_back(pair.first);
        }
        return names;
    }

    void ClearSentMessages()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sentMessages_.clear();
    }

private:
    mutable std::mutex mutex_;
    bool isAuthMaintainActive_ = true; // Default to active for companion-side tests
    std::vector<PhysicalDeviceStatus> onlineDevices_;
    std::map<std::string, std::vector<std::vector<uint8_t>>> sentMessages_;
    OnPhysicalDeviceStatusChange physicalDeviceStatusCb_;
    OnConnectionStatusChange connectionStatusCb_;
    OnRawMessage rawMessageCb_;
    OnIncomingConnection incomingConnectionCb_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FAKE_CHANNEL_H
