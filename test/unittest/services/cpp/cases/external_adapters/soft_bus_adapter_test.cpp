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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iam_logger.h"

#include "adapter_manager.h"
#include "soft_bus_adapter.h"
#include "soft_bus_adapter_impl.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace testing;
using namespace testing::ext;

class MockSoftBusAdapter : public ISoftBusAdapter {
public:
    void RegisterCallback(std::shared_ptr<ISoftBusSocketCallback> callback) override
    {
        callback_ = callback;
    }

    std::optional<int32_t> CreateServerSocket() override
    {
        int32_t returnVal = 12345;
        if (callback_ != nullptr) {
            return returnVal;
        }
        return std::nullopt;
    }

    std::optional<int32_t> CreateClientSocket(const std::string &networkId) override
    {
        int32_t returnVal = 12346;
        if (!networkId.empty() && callback_ != nullptr) {
            return returnVal;
        }
        return std::nullopt;
    }

    bool SendBytes(int32_t socket, const std::vector<uint8_t> &data) override
    {
        return socket > 0 && !data.empty();
    }

    void ShutdownSocket(int32_t socket) override
    {
    }

private:
    std::shared_ptr<ISoftBusSocketCallback> callback_;
};

class SoftBusAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void SoftBusAdapterTest::SetUpTestCase()
{
}

void SoftBusAdapterTest::TearDownTestCase()
{
}

void SoftBusAdapterTest::SetUp()
{
    AdapterManager::GetInstance().SetSoftBusAdapter(nullptr);
}

void SoftBusAdapterTest::TearDown()
{
    AdapterManager::GetInstance().SetSoftBusAdapter(nullptr);
}

HWTEST_F(SoftBusAdapterTest, CreateDefaultAdapter, TestSize.Level0)
{
    auto adapter = std::make_shared<SoftBusAdapterImpl>();
    ASSERT_NE(adapter, nullptr);
}

HWTEST_F(SoftBusAdapterTest, RegisterToSingleton, TestSize.Level0)
{
    auto adapter = std::make_shared<SoftBusAdapterImpl>();
    AdapterManager::GetInstance().SetSoftBusAdapter(adapter);

    ISoftBusAdapter &retrieved = GetSoftBusAdapter();
    EXPECT_EQ(&retrieved, adapter.get());
}

HWTEST_F(SoftBusAdapterTest, CreateServerSocketWithNullCallback, TestSize.Level0)
{
    auto adapter = std::make_shared<SoftBusAdapterImpl>();

    adapter->RegisterCallback(nullptr);
    auto result = adapter->CreateServerSocket();
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SoftBusAdapterTest, CreateClientSocketWithEmptyNetworkId, TestSize.Level0)
{
    auto adapter = std::make_shared<SoftBusAdapterImpl>();

    class MockCallback : public ISoftBusSocketCallback {
    public:
        void HandleBind(int32_t socket, const std::string &networkId) override
        {
        }
        void HandleBytes(int32_t socket, const void *data, uint32_t dataLen) override
        {
        }
        void HandleShutdown(int32_t socket, int32_t reason) override
        {
        }
        void HandleError(int32_t socket, int32_t errorCode) override
        {
        }
    };

    auto callback = std::make_shared<MockCallback>();
    adapter->RegisterCallback(callback);

    auto result = adapter->CreateClientSocket("");
    EXPECT_FALSE(result.has_value());
}

HWTEST_F(SoftBusAdapterTest, SendBytesWithInvalidSocket, TestSize.Level0)
{
    auto adapter = std::make_shared<SoftBusAdapterImpl>();

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    bool result = adapter->SendBytes(-1, data);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusAdapterTest, MockAdapterInjection, TestSize.Level0)
{
    auto mockAdapter = std::make_shared<MockSoftBusAdapter>();
    AdapterManager::GetInstance().SetSoftBusAdapter(mockAdapter);

    class MockCallback : public ISoftBusSocketCallback {
    public:
        void HandleBind(int32_t socket, const std::string &networkId) override
        {
        }
        void HandleBytes(int32_t socket, const void *data, uint32_t dataLen) override
        {
        }
        void HandleShutdown(int32_t socket, int32_t reason) override
        {
        }
        void HandleError(int32_t socket, int32_t errorCode) override
        {
        }
    };

    auto callback = std::make_shared<MockCallback>();
    auto &adapter = GetSoftBusAdapter();
    adapter.RegisterCallback(callback);

    auto socketId = adapter.CreateServerSocket();
    EXPECT_TRUE(socketId.has_value());
    EXPECT_EQ(socketId.value(), 12345);

    std::vector<uint8_t> data = { 1, 2, 3 };
    bool result = adapter.SendBytes(socketId.value(), data);
    EXPECT_TRUE(result);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
