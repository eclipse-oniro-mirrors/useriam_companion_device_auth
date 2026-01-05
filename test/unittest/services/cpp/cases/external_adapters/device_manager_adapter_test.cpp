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

#include <memory>
#include <optional>
#include <string>

#include "device_manager_adapter.h"
#include "device_manager_adapter_impl.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iam_logger.h"

#include "adapter_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace testing;
using namespace testing::ext;

class DeviceManagerAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void DeviceManagerAdapterTest::SetUpTestCase()
{
}

void DeviceManagerAdapterTest::TearDownTestCase()
{
}

void DeviceManagerAdapterTest::SetUp()
{
    AdapterManager::GetInstance().SetDeviceManagerAdapter(nullptr);
}

void DeviceManagerAdapterTest::TearDown()
{
    AdapterManager::GetInstance().SetDeviceManagerAdapter(nullptr);
}

HWTEST_F(DeviceManagerAdapterTest, CreateDefaultAdapter, TestSize.Level0)
{
    auto adapter = std::make_shared<DeviceManagerAdapterImpl>();
    ASSERT_NE(adapter, nullptr);
}

HWTEST_F(DeviceManagerAdapterTest, RegisterToSingleton, TestSize.Level0)
{
    auto adapter = std::make_shared<DeviceManagerAdapterImpl>();
    AdapterManager::GetInstance().SetDeviceManagerAdapter(adapter);

    IDeviceManagerAdapter &retrieved = GetDeviceManagerAdapter();
    EXPECT_EQ(&retrieved, adapter.get());
}

HWTEST_F(DeviceManagerAdapterTest, InitDeviceManager, TestSize.Level0)
{
    auto adapter = std::make_shared<DeviceManagerAdapterImpl>();

    // Without real DeviceManager service, this will fail
    bool result = adapter->InitDeviceManager();
    // Expected to fail in test environment
    EXPECT_FALSE(result);
}

HWTEST_F(DeviceManagerAdapterTest, GetUdidByNetworkIdWithEmptyId, TestSize.Level0)
{
    auto adapter = std::make_shared<DeviceManagerAdapterImpl>();

    auto result = adapter->GetUdidByNetworkId("");
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(DeviceManagerAdapterTest, GetUdidByNetworkIdWithValidId, TestSize.Level0)
{
    auto adapter = std::make_shared<DeviceManagerAdapterImpl>();

    auto result = adapter->GetUdidByNetworkId("test_network_id");
    // Without real DeviceManager service, this will fail
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(DeviceManagerAdapterTest, MockAdapterInjection, TestSize.Level0)
{
    // Create mock adapter
    class MockDeviceManagerAdapter : public IDeviceManagerAdapter {
    public:
        bool InitDeviceManager() override
        {
            return true;
        }

        void UnInitDeviceManager() override
        {
        }

        std::optional<std::string> GetUdidByNetworkId(const std::string &networkId) override
        {
            if (networkId == "test_network_id") {
                return std::string("mock_udid_12345");
            }
            return std::nullopt;
        }

        bool QueryTrustedDevices(std::vector<DistributedHardware::DmDeviceInfo> &deviceList) override
        {
            return true;
        }

        bool RegisterDevStatusCallback(std::shared_ptr<DistributedHardware::DeviceStatusCallback> callback) override
        {
            return true;
        }

        void UnRegisterDevStatusCallback(std::shared_ptr<DistributedHardware::DeviceStatusCallback> callback) override
        {
        }
    };

    auto mockAdapter = std::make_shared<MockDeviceManagerAdapter>();
    AdapterManager::GetInstance().SetDeviceManagerAdapter(mockAdapter);

    IDeviceManagerAdapter &adapter = GetDeviceManagerAdapter();
    auto result = adapter.GetUdidByNetworkId("test_network_id");

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "mock_udid_12345");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
