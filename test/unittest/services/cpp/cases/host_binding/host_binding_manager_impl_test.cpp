/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "companion_obtain_token_request.h"
#include "companion_revoke_token_request.h"
#include "host_binding.h"
#include "host_binding_manager_impl.h"
#include "mock_guard.h"
#include "relative_timer.h"
#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

PersistedHostBindingStatus MakePersistedStatus(BindingId bindingId, UserId companionUserId, const std::string &deviceId,
    UserId deviceUserId)
{
    PersistedHostBindingStatus status;
    status.bindingId = bindingId;
    status.companionUserId = companionUserId;
    status.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.hostDeviceKey.deviceId = deviceId;
    status.hostDeviceKey.deviceUserId = deviceUserId;
    status.isTokenValid = false;
    return status;
}

void SetupManagerCreationMocks(MockGuard &guard)
{
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));

    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
}

std::shared_ptr<HostBindingManagerImpl> CreateManager(MockGuard &guard, UserId activeUserId)
{
    SetupManagerCreationMocks(guard);
    auto manager = HostBindingManagerImpl::Create();
    if (manager) {
        manager->activeUserId_ = activeUserId;
    }
    return manager;
}

class HostBindingManagerImplTest : public Test {
public:
    // No SetUp/TearDown needed - MockGuard handles everything
};

HWTEST_F(HostBindingManagerImplTest, Create_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    EXPECT_CALL(userIdMgr, SubscribeActiveUserId(_)).WillOnce(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));

    auto manager = HostBindingManagerImpl::Create();
    EXPECT_NE(nullptr, manager);
}

HWTEST_F(HostBindingManagerImplTest, Create_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    EXPECT_CALL(userIdMgr, SubscribeActiveUserId(_)).WillOnce(Return(nullptr));

    auto manager = HostBindingManagerImpl::Create();
    EXPECT_NE(nullptr, manager);
}

HWTEST_F(HostBindingManagerImplTest, Initialize_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->Initialize();
}

HWTEST_F(HostBindingManagerImplTest, GetHostBindingStatusById_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    manager->activeUserId_ = activeUserId_;
    ResultCode ret = manager->AddBindingInternal(binding);
    EXPECT_EQ(ResultCode::SUCCESS, ret);

    auto status = manager->GetHostBindingStatus(12345);
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(12345, status->bindingId);
    EXPECT_EQ(activeUserId_, status->companionUserId);
}

HWTEST_F(HostBindingManagerImplTest, GetHostBindingStatusById_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto status = manager->GetHostBindingStatus(12345);
    EXPECT_FALSE(status.has_value());
}

HWTEST_F(HostBindingManagerImplTest, GetHostBindingStatusByDeviceUser_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    manager->activeUserId_ = activeUserId_;
    ResultCode ret = manager->AddBindingInternal(binding);
    EXPECT_EQ(ResultCode::SUCCESS, ret);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "device-1";
    deviceKey.deviceUserId = 200;

    auto status = manager->GetHostBindingStatus(activeUserId_, deviceKey);
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(12345, status->bindingId);
}

HWTEST_F(HostBindingManagerImplTest, GetHostBindingStatusByDeviceUser_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "device-1";
    deviceKey.deviceUserId = 200;

    auto status = manager->GetHostBindingStatus(activeUserId_, deviceKey);
    EXPECT_FALSE(status.has_value());
}

HWTEST_F(HostBindingManagerImplTest, GetAllHostBindingStatus_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    manager->AddBindingInternal(binding);

    auto statusList = manager->GetAllHostBindingStatus();
    EXPECT_EQ(1u, statusList.size());
}

HWTEST_F(HostBindingManagerImplTest, BeginAddHostBinding_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = 999;

    std::vector<uint8_t> request;
    std::vector<uint8_t> reply;
    ResultCode ret = manager->BeginAddHostBinding(1, activeUserId_, SecureProtocolId::DEFAULT, request, reply);

    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, BeginAddHostBinding_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    EXPECT_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    std::vector<uint8_t> request;
    std::vector<uint8_t> reply;
    ResultCode ret = manager->BeginAddHostBinding(1, activeUserId_, SecureProtocolId::DEFAULT, request, reply);

    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, BeginAddHostBinding_003, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    EXPECT_CALL(securityAgent, CompanionBeginAddHostBinding(_, _))
        .WillOnce(
            DoAll(Invoke([](const CompanionBeginAddHostBindingInput &, CompanionBeginAddHostBindingOutput &output) {
                output.addHostBindingReply.clear();
                output.hostBindingStatus.bindingId = 0;
            }),
                Return(ResultCode::SUCCESS)));

    std::vector<uint8_t> request;
    std::vector<uint8_t> reply;
    ResultCode ret = manager->BeginAddHostBinding(1, activeUserId_, SecureProtocolId::DEFAULT, request, reply);

    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, BeginAddHostBinding_004, TestSize.Level0)
{
    MockGuard guard;
    constexpr UserId activeUserId = 100;
    auto manager = CreateManager(guard, activeUserId);
    ASSERT_NE(nullptr, manager);

    auto &securityAgent = guard.GetSecurityAgent();
    EXPECT_CALL(securityAgent, CompanionBeginAddHostBinding(_, _))
        .WillOnce(
            DoAll(Invoke([](const CompanionBeginAddHostBindingInput &, CompanionBeginAddHostBindingOutput &output) {
                output.addHostBindingReply = { 1, 2, 3, 4 };
                output.hostBindingStatus.bindingId = 12345;
                output.hostBindingStatus.companionUserId = 100;
                output.hostBindingStatus.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
                output.hostBindingStatus.hostDeviceKey.deviceId = "device-1";
                output.hostBindingStatus.hostDeviceKey.deviceUserId = 200;
            }),
                Return(ResultCode::SUCCESS)));

    std::vector<uint8_t> request;
    std::vector<uint8_t> reply;
    ResultCode ret = manager->BeginAddHostBinding(1, activeUserId, SecureProtocolId::DEFAULT, request, reply);

    EXPECT_EQ(ResultCode::SUCCESS, ret);
    EXPECT_EQ(4u, reply.size());
}

HWTEST_F(HostBindingManagerImplTest, BeginAddHostBinding_005, TestSize.Level0)
{
    MockGuard guard;
    constexpr UserId activeUserId = 100;
    auto manager = CreateManager(guard, activeUserId);
    ASSERT_NE(nullptr, manager);

    auto persistedStatus = MakePersistedStatus(12346, activeUserId, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    auto &securityAgent = guard.GetSecurityAgent();
    EXPECT_CALL(securityAgent, CompanionBeginAddHostBinding(_, _))
        .WillOnce(
            DoAll(Invoke([](const CompanionBeginAddHostBindingInput &, CompanionBeginAddHostBindingOutput &output) {
                output.addHostBindingReply = { 1, 2, 3, 4 };
                output.hostBindingStatus.bindingId = 12345;
                output.hostBindingStatus.companionUserId = 100;
                output.hostBindingStatus.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
                output.hostBindingStatus.hostDeviceKey.deviceId = "device-1";
                output.hostBindingStatus.hostDeviceKey.deviceUserId = 200;
                output.replacedBindingId = 12346;
            }),
                Return(ResultCode::SUCCESS)));

    std::vector<uint8_t> request;
    std::vector<uint8_t> reply;
    ResultCode ret = manager->BeginAddHostBinding(1, activeUserId, SecureProtocolId::DEFAULT, request, reply);

    EXPECT_EQ(ResultCode::SUCCESS, ret);
    EXPECT_FALSE(manager->GetHostBindingStatus(12346).has_value());
    EXPECT_TRUE(manager->GetHostBindingStatus(12345).has_value());
}

HWTEST_F(HostBindingManagerImplTest, BeginAddHostBinding_006, TestSize.Level0)
{
    MockGuard guard;
    constexpr UserId activeUserId = 100;
    auto manager = CreateManager(guard, activeUserId);
    ASSERT_NE(nullptr, manager);

    auto &securityAgent = guard.GetSecurityAgent();
    EXPECT_CALL(securityAgent, CompanionBeginAddHostBinding(_, _))
        .WillOnce(
            DoAll(Invoke([](const CompanionBeginAddHostBindingInput &, CompanionBeginAddHostBindingOutput &output) {
                output.addHostBindingReply = { 1, 2, 3, 4 };
                output.hostBindingStatus.bindingId = 12345;
                output.hostBindingStatus.companionUserId = 100;
                output.hostBindingStatus.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
                output.hostBindingStatus.hostDeviceKey.deviceId = "device-1";
                output.hostBindingStatus.hostDeviceKey.deviceUserId = 200;
            }),
                Return(ResultCode::SUCCESS)));

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _)).WillOnce(Return(nullptr));

    std::vector<uint8_t> request = { 1, 2, 3 };
    std::vector<uint8_t> reply;
    ResultCode ret = manager->BeginAddHostBinding(1, activeUserId, SecureProtocolId::DEFAULT, request, reply);

    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, EndAddHostBinding_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    EXPECT_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ResultCode ret = manager->EndAddHostBinding(1, ResultCode::SUCCESS);
    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, EndAddHostBinding_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    EXPECT_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    ResultCode ret = manager->EndAddHostBinding(1, ResultCode::SUCCESS);
    EXPECT_EQ(ResultCode::SUCCESS, ret);
}

HWTEST_F(HostBindingManagerImplTest, EndAddHostBinding_003, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    EXPECT_CALL(securityAgent, CompanionEndAddHostBinding(_, _))
        .WillOnce(DoAll(Invoke([](const CompanionEndAddHostBindingInput &, CompanionEndAddHostBindingOutput &output) {
            output.bindingId = 12345;
        }),
            Return(ResultCode::SUCCESS)));

    ResultCode ret = manager->EndAddHostBinding(1, ResultCode::GENERAL_ERROR);
    EXPECT_EQ(ResultCode::SUCCESS, ret);
    EXPECT_FALSE(manager->GetHostBindingStatus(12345).has_value());
}

HWTEST_F(HostBindingManagerImplTest, RemoveHostBinding_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "device-1";
    deviceKey.deviceUserId = 200;

    ResultCode ret = manager->RemoveHostBinding(activeUserId_, deviceKey);
    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, RemoveHostBinding_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "device-1";
    deviceKey.deviceUserId = 200;

    EXPECT_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ResultCode ret = manager->RemoveHostBinding(activeUserId_, deviceKey);
    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, RemoveHostBinding_003, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "device-1";
    deviceKey.deviceUserId = 200;

    EXPECT_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillOnce(Return(ResultCode::SUCCESS));

    ResultCode ret = manager->RemoveHostBinding(activeUserId_, deviceKey);
    EXPECT_EQ(ResultCode::SUCCESS, ret);
    EXPECT_FALSE(manager->GetHostBindingStatus(12345).has_value());
}

HWTEST_F(HostBindingManagerImplTest, SetHostBindingTokenValid_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    bool result = manager->SetHostBindingTokenValid(12345, true);
    EXPECT_FALSE(result);
}

HWTEST_F(HostBindingManagerImplTest, SetHostBindingTokenValid_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    bool result = manager->SetHostBindingTokenValid(12345, true);
    EXPECT_TRUE(result);

    auto status = manager->GetHostBindingStatus(12345);
    ASSERT_TRUE(status.has_value());
    EXPECT_TRUE(status->isTokenValid);
}

HWTEST_F(HostBindingManagerImplTest, OnActiveUserIdChanged_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    manager->OnActiveUserIdChanged(activeUserId_);

    auto status = manager->GetHostBindingStatus(12345);
    EXPECT_TRUE(status.has_value());
}

HWTEST_F(HostBindingManagerImplTest, OnActiveUserIdChanged_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    EXPECT_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillOnce(Return(ResultCode::SUCCESS));

    manager->OnActiveUserIdChanged(200);

    EXPECT_FALSE(manager->GetHostBindingStatus(12345).has_value());
    EXPECT_EQ(200, manager->activeUserId_);
}

HWTEST_F(HostBindingManagerImplTest, OnActiveUserIdChanged_003, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    manager->OnActiveUserIdChanged(INVALID_USER_ID);

    EXPECT_FALSE(manager->GetHostBindingStatus(12345).has_value());
    EXPECT_EQ(INVALID_USER_ID, manager->activeUserId_);
}

HWTEST_F(HostBindingManagerImplTest, OnActiveUserIdChanged_004, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = INVALID_USER_ID;

    EXPECT_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    manager->OnActiveUserIdChanged(activeUserId_);

    EXPECT_EQ(activeUserId_, manager->activeUserId_);
}

HWTEST_F(HostBindingManagerImplTest, OnActiveUserIdChanged_005, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = INVALID_USER_ID;

    std::vector<PersistedHostBindingStatus> persistedList;
    persistedList.push_back(MakePersistedStatus(12345, activeUserId_, "device-1", 200));

    EXPECT_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _))
        .WillOnce(DoAll(Invoke([persistedList](const CompanionGetPersistedHostBindingStatusInput &,
                                   CompanionGetPersistedHostBindingStatusOutput &output) {
            output.hostBindingStatusList = persistedList;
        }),
            Return(ResultCode::SUCCESS)));

    manager->OnActiveUserIdChanged(activeUserId_);

    EXPECT_EQ(activeUserId_, manager->activeUserId_);
    EXPECT_TRUE(manager->GetHostBindingStatus(12345).has_value());
}

HWTEST_F(HostBindingManagerImplTest, AddBindingInternal_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    ResultCode ret = manager->AddBindingInternal(nullptr);
    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, AddBindingInternal_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    ResultCode ret = manager->AddBindingInternal(binding);
    EXPECT_EQ(ResultCode::SUCCESS, ret);
}

HWTEST_F(HostBindingManagerImplTest, AddBindingInternal_003, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding1 = HostBinding::Create(persistedStatus);
    auto binding2 = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding1);
    ASSERT_NE(nullptr, binding2);

    manager->AddBindingInternal(binding1);
    ResultCode ret = manager->AddBindingInternal(binding2);
    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, AddBindingInternal_004, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto status1 = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto status2 = MakePersistedStatus(12346, activeUserId_, "device-1", 200);

    auto binding1 = HostBinding::Create(status1);
    auto binding2 = HostBinding::Create(status2);
    ASSERT_NE(nullptr, binding1);
    ASSERT_NE(nullptr, binding2);

    manager->AddBindingInternal(binding1);
    ResultCode ret = manager->AddBindingInternal(binding2);
    EXPECT_EQ(ResultCode::SUCCESS, ret);

    EXPECT_FALSE(manager->GetHostBindingStatus(12345).has_value());
    EXPECT_TRUE(manager->GetHostBindingStatus(12346).has_value());
}

HWTEST_F(HostBindingManagerImplTest, RemoveBindingInternal_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    ResultCode ret = manager->RemoveBindingInternal(12345);
    EXPECT_EQ(ResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(HostBindingManagerImplTest, RemoveBindingInternal_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    ResultCode ret = manager->RemoveBindingInternal(12345);
    EXPECT_EQ(ResultCode::SUCCESS, ret);
    EXPECT_FALSE(manager->GetHostBindingStatus(12345).has_value());
}

HWTEST_F(HostBindingManagerImplTest, StartObtainTokenRequests_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = 999;

    std::vector<uint8_t> fwkMsg;
    manager->StartObtainTokenRequests(activeUserId_, fwkMsg);
}

HWTEST_F(HostBindingManagerImplTest, StartObtainTokenRequests_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    std::vector<uint8_t> fwkMsg;
    manager->StartObtainTokenRequests(activeUserId_, fwkMsg);
}

HWTEST_F(HostBindingManagerImplTest, StartObtainTokenRequests_003, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    EXPECT_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _)).WillOnce(Return(nullptr));

    std::vector<uint8_t> fwkMsg;
    manager->StartObtainTokenRequests(activeUserId_, fwkMsg);
}

HWTEST_F(HostBindingManagerImplTest, StartObtainTokenRequests_004, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    EXPECT_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillOnce(Invoke([this](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    EXPECT_CALL(requestMgr, Start(_)).WillOnce(Return(false));

    std::vector<uint8_t> fwkMsg;
    manager->StartObtainTokenRequests(activeUserId_, fwkMsg);
}

HWTEST_F(HostBindingManagerImplTest, StartObtainTokenRequests_005, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    manager->AddBindingInternal(binding);

    EXPECT_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillOnce(Invoke([this](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    EXPECT_CALL(requestMgr, Start(_)).WillOnce(Return(true));

    std::vector<uint8_t> fwkMsg;
    manager->StartObtainTokenRequests(activeUserId_, fwkMsg);
}

HWTEST_F(HostBindingManagerImplTest, RevokeTokens_001, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = 999;

    manager->RevokeTokens(activeUserId_);
}

HWTEST_F(HostBindingManagerImplTest, RevokeTokens_002, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    manager->RevokeTokens(activeUserId_);
}

HWTEST_F(HostBindingManagerImplTest, RevokeTokens_003, TestSize.Level0)
{
    MockGuard guard;
    int32_t activeUserId_ = 100;
    (void)activeUserId_;
    auto &userIdMgr = guard.GetUserIdManager();
    ON_CALL(userIdMgr, SubscribeActiveUserId(_)).WillByDefault(Invoke([](ActiveUserIdCallback &&) {
        return MakeSubscription();
    }));
    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    ON_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _))
        .WillByDefault(Invoke([](const DeviceKey &, OnDeviceStatusChange &&) { return MakeSubscription(); }));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillByDefault(Invoke([](std::function<void(bool)> &&) {
        return MakeSubscription();
    }));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));
    auto &securityAgent = guard.GetSecurityAgent();
    ON_CALL(securityAgent, CompanionBeginAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionEndAddHostBinding(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRemoveHostBinding(_)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionGetPersistedHostBindingStatus(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
    ON_CALL(securityAgent, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionObtainTokenRequest(_, _))
        .WillByDefault(Invoke([](const DeviceKey &hostDeviceKey, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<CompanionObtainTokenRequest>(hostDeviceKey, fwkUnlockMsg);
        }));
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _))
        .WillByDefault(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));
    auto manager = HostBindingManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->activeUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);
    binding->SetTokenValid(true);
    manager->AddBindingInternal(binding);

    manager->RevokeTokens(activeUserId_);

    auto status = manager->GetHostBindingStatus(12345);
    ASSERT_TRUE(status.has_value());
    EXPECT_FALSE(status->isTokenValid);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
