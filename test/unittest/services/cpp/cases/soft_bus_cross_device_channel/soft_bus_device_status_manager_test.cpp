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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_device_manager_adapter.h"
#include "mock_guard.h"
#include "soft_bus_adapter_manager.h"
#include "soft_bus_device_status_manager.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint64_t UINT64_1 = 1;

class SoftBusDeviceStatusManagerTest : public testing::Test {
protected:
    uint64_t nextGlobalId_ = UINT64_1;
    NiceMock<MockDeviceManagerAdapter> mockDeviceManagerAdapter_;
};

HWTEST_F(SoftBusDeviceStatusManagerTest, Create_001, TestSize.Level0)
{
    MockGuard guard;

    {
        auto manager = SoftBusDeviceStatusManager::Create();
        EXPECT_NE(manager, nullptr);
    }
}

HWTEST_F(SoftBusDeviceStatusManagerTest, Start_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    bool result = manager->Start();
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, Start_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->started_ = true;

    bool result = manager->Start();
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, GetLocalPhysicalDeviceKey_001, TestSize.Level0)
{
    MockGuard guard;
    auto &miscManager = guard.GetMiscManager();
    ON_CALL(miscManager, GetLocalUdid()).WillByDefault(Return(std::optional<std::string>("test-local-udid")));

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto key = manager->GetLocalPhysicalDeviceKey();
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(key.value().idType, DeviceIdType::UNIFIED_DEVICE_ID);
    EXPECT_EQ(key.value().deviceId, "test-local-udid");
}

HWTEST_F(SoftBusDeviceStatusManagerTest, GetLocalPhysicalDeviceKey_002, TestSize.Level0)
{
    MockGuard guard;
    auto &miscManager = guard.GetMiscManager();

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    EXPECT_CALL(miscManager, GetLocalUdid()).WillOnce(Return(std::nullopt));

    auto key = manager->GetLocalPhysicalDeviceKey();
    EXPECT_FALSE(key.has_value());
}

HWTEST_F(SoftBusDeviceStatusManagerTest, GetAuthMaintainActive_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    bool isActive = manager->GetAuthMaintainActive();
    EXPECT_FALSE(isActive);

    manager->isLocalAuthMaintainActive_ = true;
    isActive = manager->GetAuthMaintainActive();
    EXPECT_TRUE(isActive);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, GetAllPhysicalDevices_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto devices = manager->GetAllPhysicalDevices();
    EXPECT_TRUE(devices.empty());
}

HWTEST_F(SoftBusDeviceStatusManagerTest, GetPhysicalDeviceStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    auto status = manager->GetPhysicalDeviceStatus(key);
    EXPECT_FALSE(status.has_value());
}

HWTEST_F(SoftBusDeviceStatusManagerTest, GetPhysicalDeviceStatus_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    key.deviceId = "test-device";

    PhysicalDeviceStatus physicalDeviceStatus;
    physicalDeviceStatus.physicalDeviceKey = key;
    manager->physicalDeviceStatus_.push_back(physicalDeviceStatus);

    auto status = manager->GetPhysicalDeviceStatus(key);
    EXPECT_TRUE(status.has_value());
}

HWTEST_F(SoftBusDeviceStatusManagerTest, SubscribePhysicalDeviceStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribePhysicalDeviceStatus(
        [&callbackInvoked](const std::vector<PhysicalDeviceStatus> &) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, SubscribePhysicalDeviceStatus_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribePhysicalDeviceStatus(nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, SubscribeAuthMaintainActive_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });

    EXPECT_NE(subscription, nullptr);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, SubscribeAuthMaintainActive_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto subscription = manager->SubscribeAuthMaintainActive(nullptr);
    EXPECT_EQ(subscription, nullptr);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, HandleLocalIsAuthMaintainActiveChange_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    bool receivedValue = false;
    auto subscription = manager->SubscribeAuthMaintainActive([&callbackInvoked, &receivedValue](bool isActive) {
        callbackInvoked = true;
        receivedValue = isActive;
    });

    manager->HandleLocalIsAuthMaintainActiveChange(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
    EXPECT_TRUE(receivedValue);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, HandleLocalIsAuthMaintainActiveChange_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);
    manager->isLocalAuthMaintainActive_ = true;

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });

    manager->HandleLocalIsAuthMaintainActiveChange(true);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, HandleLocalIsAuthMaintainActiveChange_003, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->authMaintainActiveSubscribers_[1] = nullptr;

    manager->HandleLocalIsAuthMaintainActiveChange(true);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusDeviceStatusManagerTest, UnsubscribePhysicalDeviceStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    {
        auto subscription = manager->SubscribePhysicalDeviceStatus(
            [&callbackInvoked](const std::vector<PhysicalDeviceStatus> &) { callbackInvoked = true; });
        EXPECT_NE(subscription, nullptr);
        EXPECT_FALSE(manager->physicalDeviceStatusSubscribers_.empty());
    }

    EXPECT_TRUE(manager->physicalDeviceStatusSubscribers_.empty());
}

HWTEST_F(SoftBusDeviceStatusManagerTest, UnsubscribeAuthMaintainActive_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    {
        auto subscription = manager->SubscribeAuthMaintainActive([&callbackInvoked](bool) { callbackInvoked = true; });
        EXPECT_NE(subscription, nullptr);
        EXPECT_FALSE(manager->authMaintainActiveSubscribers_.empty());
    }

    EXPECT_TRUE(manager->authMaintainActiveSubscribers_.empty());
}

HWTEST_F(SoftBusDeviceStatusManagerTest, NotifyDeviceStatusChange_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->NotifyDeviceStatusChange();
}

HWTEST_F(SoftBusDeviceStatusManagerTest, NotifyDeviceStatusChange_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribePhysicalDeviceStatus(
        [&callbackInvoked](const std::vector<PhysicalDeviceStatus> &) { callbackInvoked = true; });
    EXPECT_NE(subscription, nullptr);

    manager->NotifyDeviceStatusChange();
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(SoftBusDeviceStatusManagerTest, NotifyDeviceStatusChange_003, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->physicalDeviceStatusSubscribers_[1] = nullptr;

    manager->NotifyDeviceStatusChange();
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusDeviceStatusManagerTest, Destructor_001, TestSize.Level0)
{
    MockGuard guard;

    {
        auto manager = SoftBusDeviceStatusManager::Create();
        ASSERT_NE(manager, nullptr);
    }
}

HWTEST_F(SoftBusDeviceStatusManagerTest, IsDeviceTypeIdSupport_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    EXPECT_TRUE(manager->IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE));
    EXPECT_TRUE(manager->IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD));
    EXPECT_TRUE(manager->IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1));
    EXPECT_TRUE(manager->IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType::DEVICE_TYPE_PC));
    EXPECT_TRUE(manager->IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType::DEVICE_TYPE_UNKNOWN));
    EXPECT_FALSE(manager->IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH));
    EXPECT_FALSE(manager->IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType::DEVICE_TYPE_TV));
    EXPECT_FALSE(manager->IsDeviceTypeIdSupport(DistributedHardware::DmDeviceType::DEVICE_TYPE_SMART_DISPLAY));
}

HWTEST_F(SoftBusDeviceStatusManagerTest, DeviceTypeIdToString_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    EXPECT_EQ(manager->DeviceTypeIdToString(DistributedHardware::DmDeviceType::DEVICE_TYPE_PC), "pc");
    EXPECT_EQ(manager->DeviceTypeIdToString(DistributedHardware::DmDeviceType::DEVICE_TYPE_PHONE), "phone");
    EXPECT_EQ(manager->DeviceTypeIdToString(DistributedHardware::DmDeviceType::DEVICE_TYPE_PAD), "pad");
    EXPECT_EQ(manager->DeviceTypeIdToString(DistributedHardware::DmDeviceType::DEVICE_TYPE_2IN1), "2in1");
    EXPECT_EQ(manager->DeviceTypeIdToString(DistributedHardware::DmDeviceType::DEVICE_TYPE_UNKNOWN), "unknown");
    EXPECT_EQ(manager->DeviceTypeIdToString(DistributedHardware::DmDeviceType::DEVICE_TYPE_WATCH), "unknown");
    EXPECT_EQ(manager->DeviceTypeIdToString(DistributedHardware::DmDeviceType::DEVICE_TYPE_TV), "unknown");
    EXPECT_EQ(manager->DeviceTypeIdToString(DistributedHardware::DmDeviceType::DEVICE_TYPE_SMART_DISPLAY), "unknown");
}

HWTEST_F(SoftBusDeviceStatusManagerTest, GenerateDeviceModelInfo_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    auto info = manager->GenerateDeviceModelInfo(DistributedHardware::DmDeviceType::DEVICE_TYPE_PC);
    EXPECT_EQ(info, "{\"deviceType\":\"pc\",\"type\":\"deviceType\"}");
}

HWTEST_F(SoftBusDeviceStatusManagerTest, HandleDeviceManagerServiceReady_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleDeviceManagerServiceReady();
    manager->HandleDeviceManagerServiceReady();
}

HWTEST_F(SoftBusDeviceStatusManagerTest, HandleDeviceManagerServiceUnavailable_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleDeviceManagerServiceUnavailable();
}

HWTEST_F(SoftBusDeviceStatusManagerTest, HandleDeviceManagerServiceUnavailable_002, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    manager->HandleDeviceManagerServiceReady();
    manager->HandleDeviceManagerServiceUnavailable();
}

HWTEST_F(SoftBusDeviceStatusManagerTest, RefreshDeviceStatus_001, TestSize.Level0)
{
    MockGuard guard;

    auto manager = SoftBusDeviceStatusManager::Create();
    ASSERT_NE(manager, nullptr);

    PhysicalDeviceStatus status;
    manager->physicalDeviceStatus_.push_back(status);

    manager->RefreshDeviceStatus();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
