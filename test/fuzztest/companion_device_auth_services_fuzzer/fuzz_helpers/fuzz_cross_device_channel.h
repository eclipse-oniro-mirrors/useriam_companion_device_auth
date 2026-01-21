/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_FUZZ_CROSS_DEVICE_CHANNEL_H
#define COMPANION_DEVICE_AUTH_FUZZ_CROSS_DEVICE_CHANNEL_H

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "cross_device_comm/icross_device_channel.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
inline std::vector<uint8_t> GetFuzzSampleMessage()
{
    return { 1, 2, 3, 4 };
}
} // namespace

// Simple cross-device channel implementation for fuzzing
// Provides non-deterministic behavior based on FuzzedDataProvider
class FuzzCrossDeviceChannel : public ICrossDeviceChannel {
public:
    explicit FuzzCrossDeviceChannel(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
        channelId_ = GenerateFuzzChannelId(fuzzData);
    }

    bool Start() override
    {
        return fuzzData_.ConsumeBool();
    }

    ChannelId GetChannelId() const override
    {
        return channelId_;
    }

    std::optional<PhysicalDeviceKey> GetLocalPhysicalDeviceKey() const override
    {
        PhysicalDeviceKey key;
        key.idType = GenerateFuzzDeviceIdType(fuzzData_);
        key.deviceId = GenerateFuzzString(fuzzData_, TEST_VAL64);
        return key;
    }

    bool OpenConnection(const std::string &connectionName, const PhysicalDeviceKey &physicalDeviceKey) override
    {
        (void)connectionName;
        (void)physicalDeviceKey;
        return fuzzData_.ConsumeBool();
    }

    void CloseConnection(const std::string &connectionName) override
    {
        (void)connectionName;
    }

    bool SendMessage(const std::string &connectionName, const std::vector<uint8_t> &rawMsg) override
    {
        (void)connectionName;
        (void)rawMsg;
        return fuzzData_.ConsumeBool();
    }

    std::unique_ptr<Subscription> SubscribePhysicalDeviceStatus(OnPhysicalDeviceStatusChange &&callback) override
    {
        int num = 3;
        if (callback) {
            std::vector<PhysicalDeviceStatus> statusList;
            for (int i = 0; i < num; ++i) {
                PhysicalDeviceStatus status;
                status.physicalDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData_);
                status.physicalDeviceKey.deviceId = GenerateFuzzString(fuzzData_, TEST_VAL64);
                status.channelId = channelId_;
                status.deviceName = "FuzzDevice";
                status.deviceModelInfo = "FuzzModel";
                statusList.push_back(status);
            }
            callback(statusList);
        }
        return std::make_unique<Subscription>([] {});
    }

    std::vector<PhysicalDeviceStatus> GetAllPhysicalDevices() const override
    {
        std::vector<PhysicalDeviceStatus> devices;
        if (fuzzData_.ConsumeBool()) {
            PhysicalDeviceStatus status;
            status.physicalDeviceKey.idType = GenerateFuzzDeviceIdType(fuzzData_);
            status.physicalDeviceKey.deviceId = GenerateFuzzString(fuzzData_, TEST_VAL64);
            status.channelId = channelId_;
            status.deviceName = "FuzzDevice";
            status.deviceModelInfo = "FuzzModel";
            devices.push_back(status);
        }
        return devices;
    }

    std::unique_ptr<Subscription> SubscribeRawMessage(OnRawMessage &&callback) override
    {
        if (callback) {
            std::string connectionName = "fuzz_connection";
            std::vector<uint8_t> rawMsg = GetFuzzSampleMessage();
            callback(connectionName, rawMsg);
        }
        return std::make_unique<Subscription>([] {});
    }

    std::unique_ptr<Subscription> SubscribeConnectionStatus(OnConnectionStatusChange &&callback) override
    {
        if (callback) {
            std::string connectionName = "fuzz_connection";
            ConnectionStatus status = ConnectionStatus::CONNECTED;
            std::string reason = "fuzz_reason";
            callback(connectionName, status, reason);
        }
        return std::make_unique<Subscription>([] {});
    }

    std::unique_ptr<Subscription> SubscribeIncomingConnection(OnIncomingConnection &&callback) override
    {
        if (callback) {
            std::string connectionName = "fuzz_connection";
            PhysicalDeviceKey remotePhysicalKey;
            remotePhysicalKey.idType = GenerateFuzzDeviceIdType(fuzzData_);
            remotePhysicalKey.deviceId = GenerateFuzzString(fuzzData_, TEST_VAL64);
            callback(connectionName, remotePhysicalKey);
        }
        return std::make_unique<Subscription>([] {});
    }

    bool GetAuthMaintainActive() const override
    {
        return fuzzData_.ConsumeBool();
    }

    std::unique_ptr<Subscription> SubscribeAuthMaintainActive(OnAuthMaintainActiveChange &&callback) override
    {
        if (callback) {
            bool isActive = fuzzData_.ConsumeBool();
            callback(isActive);
        }
        return std::make_unique<Subscription>([] {});
    }

    SecureProtocolId GetCompanionSecureProtocolId() const override
    {
        return GenerateFuzzSecureProtocolId(fuzzData_);
    }

    bool CheckOperationIntent(const DeviceKey &deviceKey, uint32_t tokenId,
        OnCheckOperationIntentResult &&resultCallback) override
    {
        (void)deviceKey;
        (void)tokenId;
        if (resultCallback) {
            bool result = fuzzData_.ConsumeBool();
            resultCallback(result);
        }
        return fuzzData_.ConsumeBool();
    }

    bool RequiresDisconnectNotification() const override
    {
        return fuzzData_.ConsumeBool();
    }

    void OnRemoteDisconnect(const std::string &connectionName, const std::string &reason) override
    {
        (void)connectionName;
        (void)reason;
    }

private:
    FuzzedDataProvider &fuzzData_;
    ChannelId channelId_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FUZZ_CROSS_DEVICE_CHANNEL_H
