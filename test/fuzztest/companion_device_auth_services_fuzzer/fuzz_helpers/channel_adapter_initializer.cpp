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

#include "channel_adapter_initializer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "fuzz_constants.h"

#include "device_manager_adapter.h"
#include "soft_bus_adapter.h"
#include "soft_bus_adapter_manager.h"

#include "fuzz_data_generator.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Mock SoftBusAdapter for SoftBus channel
class MockSoftBusAdapterForChannel : public ISoftBusAdapter {
public:
    explicit MockSoftBusAdapterForChannel(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    void RegisterCallback(std::shared_ptr<ISoftBusSocketCallback> callback) override
    {
        (void)callback;
    }

    std::optional<SocketId> CreateServerSocket() override
    {
        if (fuzzData_.ConsumeBool()) {
            return fuzzData_.ConsumeIntegral<SocketId>();
        }
        return std::optional<SocketId>();
    }

    std::optional<SocketId> CreateClientSocket(const std::string &connectionName, const std::string &networkId) override
    {
        (void)connectionName;
        (void)networkId;
        if (fuzzData_.ConsumeBool()) {
            return fuzzData_.ConsumeIntegral<SocketId>();
        }
        return std::optional<SocketId>();
    }

    bool SendBytes(int32_t socketId, const std::vector<uint8_t> &data) override
    {
        (void)socketId;
        (void)data;
        return fuzzData_.ConsumeBool();
    }

    void ShutdownSocket(int32_t socketId) override
    {
        (void)socketId;
    }

private:
    FuzzedDataProvider &fuzzData_;
};

// Mock DeviceManagerAdapter for SoftBus channel
class MockDeviceManagerAdapterForChannel : public IDeviceManagerAdapter {
public:
    explicit MockDeviceManagerAdapterForChannel(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    bool InitDeviceManager() override
    {
        return fuzzData_.ConsumeBool();
    }

    void UnInitDeviceManager() override
    {
    }

    std::optional<std::string> GetUdidByNetworkId(const std::string &networkId) override
    {
        (void)networkId;
        if (fuzzData_.ConsumeBool()) {
            return GenerateRandomString(fuzzData_);
        }
        return std::optional<std::string>();
    }

    bool QueryTrustedDevices(std::vector<DmDeviceInfo> &deviceList) override
    {
        (void)deviceList;
        return fuzzData_.ConsumeBool();
    }

    bool RegisterDevStatusCallback(std::shared_ptr<DmDeviceStatusCallback> callback) override
    {
        (void)callback;
        return fuzzData_.ConsumeBool();
    }

    void UnRegisterDevStatusCallback(std::shared_ptr<DmDeviceStatusCallback> callback) override
    {
        (void)callback;
    }

private:
    FuzzedDataProvider &fuzzData_;
};

bool InitSoftBusAdapter(FuzzedDataProvider &fuzzData)
{
    auto softBusAdapter = std::make_shared<MockSoftBusAdapterForChannel>(fuzzData);
    SoftBusAdapterManager::GetInstance().SetSoftBusAdapter(softBusAdapter);

    auto deviceMgrAdapter = std::make_shared<MockDeviceManagerAdapterForChannel>(fuzzData);
    SoftBusAdapterManager::GetInstance().SetDeviceManagerAdapter(deviceMgrAdapter);

    return true;
}

void CleanupSoftBusAdapter()
{
    SoftBusAdapterManager::GetInstance().Reset();
}

bool InitializeChannelAdapters(FuzzedDataProvider &fuzzData)
{
    (void)InitSoftBusAdapter(fuzzData);
    return true;
}

void CleanupChannelAdapters()
{
    CleanupSoftBusAdapter();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
