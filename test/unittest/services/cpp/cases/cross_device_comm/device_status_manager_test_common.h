/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_DEVICE_STATUS_MANAGER_TEST_COMMON_H
#define COMPANION_DEVICE_AUTH_DEVICE_STATUS_MANAGER_TEST_COMMON_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_cross_device_channel.h"
#include "mock_guard.h"

#include "channel_manager.h"
#include "connection_manager.h"
#include "device_status_manager.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

inline constexpr int32_t INT32_100 = 100;
inline constexpr int32_t INT32_999 = 999;
inline constexpr int32_t INT32_99999 = 99999;

inline std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

inline PhysicalDeviceStatus MakePhysicalStatus(const std::string &deviceId, ChannelId channelId,
    const std::string &name)
{
    PhysicalDeviceStatus status;
    status.physicalDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.physicalDeviceKey.deviceId = deviceId;
    status.channelId = channelId;
    status.deviceName = name;
    status.deviceModelInfo = "model-" + deviceId;
    status.networkId = "network-" + deviceId;
    status.isAuthMaintainActive = true;
    return status;
}

class DeviceStatusManagerTest : public testing::Test {
protected:
    struct TestContext {
        std::unique_ptr<MockGuard> guard;
        std::shared_ptr<testing::NiceMock<MockCrossDeviceChannel>> mockChannel;
        std::shared_ptr<ChannelManager> channelMgr;
        std::shared_ptr<ConnectionManager> connectionMgr;
        std::shared_ptr<LocalDeviceStatusManager> localStatusManager;
        std::shared_ptr<DeviceStatusManager> manager;
        uint64_t nextSubscriptionId = 1;
    };

    TestContext SetupTestContext()
    {
        TestContext ctx;
        ctx.guard = std::make_unique<MockGuard>();
        ctx.mockChannel = InitMockChannel();
        ctx.channelMgr = std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> {
            std::static_pointer_cast<ICrossDeviceChannel>(ctx.mockChannel) });

        ON_CALL(ctx.guard->GetUserKeyManager(), GetUnlockedActiveUserkey)
            .WillByDefault(testing::Return(UserKey { activeUserId_, INVALID_SUB_PROFILE_ID }));

        DeviceCapabilityInfo deviceCapabilityInfo = { {},
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN }, {},
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } };
        ctx.localStatusManager = LocalDeviceStatusManager::Create(ctx.channelMgr, deviceCapabilityInfo, false);
        EXPECT_NE(ctx.localStatusManager, nullptr);

        ctx.connectionMgr = ConnectionManager::Create(ctx.channelMgr, ctx.localStatusManager);
        EXPECT_NE(ctx.connectionMgr, nullptr);

        ON_CALL(ctx.guard->GetMiscManager(), GetNextGlobalId).WillByDefault([&ctx]() mutable {
            return ctx.nextSubscriptionId++;
        });

        ctx.manager = DeviceStatusManager::Create({ BusinessId::DEFAULT }, ctx.connectionMgr, ctx.channelMgr,
            ctx.localStatusManager);
        if (ctx.manager == nullptr) {
            return ctx;
        }

        return ctx;
    }

    TestContext SetupTestContextWithBusinessIds(const std::vector<BusinessId> &hostBusinessIds)
    {
        TestContext ctx;
        ctx.guard = std::make_unique<MockGuard>();
        ctx.mockChannel = InitMockChannel();
        ctx.channelMgr = std::make_shared<ChannelManager>(std::vector<std::shared_ptr<ICrossDeviceChannel>> {
            std::static_pointer_cast<ICrossDeviceChannel>(ctx.mockChannel) });

        ON_CALL(ctx.guard->GetUserKeyManager(), SubscribeUnlockedActiveUserKey)
            .WillByDefault(testing::Invoke([](UnlockedActiveUserKeyCallback &&) { return MakeSubscription(); }));
        ON_CALL(ctx.guard->GetUserKeyManager(), GetUnlockedActiveUserkey)
            .WillByDefault(testing::Return(UserKey { activeUserId_, INVALID_SUB_PROFILE_ID }));

        DeviceCapabilityInfo deviceCapabilityInfo = { {},
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN }, {},
            { Capability::DELEGATE_AUTH, Capability::TOKEN_AUTH, Capability::OBTAIN_TOKEN } };
        ctx.localStatusManager = LocalDeviceStatusManager::Create(ctx.channelMgr, deviceCapabilityInfo, false);
        EXPECT_NE(ctx.localStatusManager, nullptr);

        ctx.connectionMgr = ConnectionManager::Create(ctx.channelMgr, ctx.localStatusManager);
        EXPECT_NE(ctx.connectionMgr, nullptr);

        ON_CALL(ctx.guard->GetMiscManager(), GetNextGlobalId).WillByDefault([&ctx]() mutable {
            return ctx.nextSubscriptionId++;
        });

        ctx.manager =
            DeviceStatusManager::Create(hostBusinessIds, ctx.connectionMgr, ctx.channelMgr, ctx.localStatusManager);
        if (ctx.manager == nullptr) {
            return ctx;
        }

        return ctx;
    }

    DeviceKey MakeDeviceKey(const PhysicalDeviceKey &physicalKey) const
    {
        DeviceKey deviceKey;
        deviceKey.idType = physicalKey.idType;
        deviceKey.deviceId = physicalKey.deviceId;
        deviceKey.deviceUserId = activeUserId_;
        return deviceKey;
    }

    std::shared_ptr<testing::NiceMock<MockCrossDeviceChannel>> InitMockChannel()
    {
        auto mockChannel = std::make_shared<testing::NiceMock<MockCrossDeviceChannel>>();
        ON_CALL(*mockChannel, GetChannelId).WillByDefault(testing::Return(ChannelId::SOFTBUS));
        ON_CALL(*mockChannel, GetAllPhysicalDevices)
            .WillByDefault(testing::Return(std::vector<PhysicalDeviceStatus> {}));
        localPhysicalKey_.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        localPhysicalKey_.deviceId = "local-device";
        ON_CALL(*mockChannel, GetLocalPhysicalDeviceKey).WillByDefault(testing::Return(localPhysicalKey_));
        ON_CALL(*mockChannel, SubscribeAuthMaintainActive)
            .WillByDefault(testing::Invoke([](OnAuthMaintainActiveChange &&) { return MakeSubscription(); }));
        ON_CALL(*mockChannel, GetAuthMaintainActive).WillByDefault(testing::Return(false));
        ON_CALL(*mockChannel, GetCompanionSecureProtocolId).WillByDefault(testing::Return(SecureProtocolId::DEFAULT));
        ON_CALL(*mockChannel, SubscribePhysicalDeviceStatus)
            .WillByDefault(testing::Invoke([](OnPhysicalDeviceStatusChange &&) { return MakeSubscription(); }));
        ON_CALL(*mockChannel, SubscribeConnectionStatus).WillByDefault(testing::Invoke([](OnConnectionStatusChange &&) {
            return MakeSubscription();
        }));
        ON_CALL(*mockChannel, SubscribeIncomingConnection).WillByDefault(testing::Invoke([](OnIncomingConnection &&) {
            return MakeSubscription();
        }));
        return mockChannel;
    }

    int32_t activeUserId_ { INT32_100 };
    PhysicalDeviceKey localPhysicalKey_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_DEVICE_STATUS_MANAGER_TEST_COMMON_H
