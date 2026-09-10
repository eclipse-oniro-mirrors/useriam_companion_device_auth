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

#include "mock_guard.h"

#include "companion_revoke_token_request.h"
#include "host_binding.h"
#include "mock_request.h"
#include "relative_timer.h"
#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_200 = 200;
constexpr uint32_t UINT32_12345 = 12345;

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
    status.companionSubProfileId = INVALID_SUB_PROFILE_ID;
    return status;
}

DeviceStatus MakeDeviceStatus(const DeviceKey &deviceKey, bool isOnline = true)
{
    DeviceStatus status;
    status.deviceKey = deviceKey;
    status.isOnline = isOnline;
    status.isAuthMaintainActive = true;
    status.deviceName = "TestDevice";
    status.deviceUserName = "TestUser";
    status.deviceModelInfo = "TestModel";
    status.protocolId = ProtocolId::VERSION_1;
    return status;
}

class HostBindingTest : public Test {
public:
    // No SetUp/TearDown needed - MockGuard handles everything
};

HWTEST_F(HostBindingTest, Create_001, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);

    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _)).WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillOnce(Return(ByMove(MakeSubscription())));

    auto binding = HostBinding::Create(persistedStatus);

    EXPECT_NE(nullptr, binding);
    EXPECT_EQ(UINT32_12345, binding->GetBindingId());
    EXPECT_EQ(INT32_100, binding->GetCompanionUserId());
    EXPECT_EQ("test_device_id", binding->GetHostDeviceKey().deviceId);
}

HWTEST_F(HostBindingTest, Create_002, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);

    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _)).WillOnce(Return(nullptr));

    auto binding = HostBinding::Create(persistedStatus);

    EXPECT_EQ(nullptr, binding);
}

HWTEST_F(HostBindingTest, Create_003, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);

    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _)).WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_)).WillOnce(Return(nullptr));

    auto binding = HostBinding::Create(persistedStatus);

    EXPECT_EQ(nullptr, binding);
}

HWTEST_F(HostBindingTest, HandleDeviceStatusChanged_001, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    DeviceKey deviceKey = persistedStatus.hostDeviceKey;
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    auto deviceStatus = MakeDeviceStatus(deviceKey, true);
    std::vector<DeviceStatus> statusList { deviceStatus };
    binding->HandleDeviceStatusChanged(statusList);

    auto status = binding->GetStatus();
    EXPECT_TRUE(status.hostDeviceStatus.isOnline);
}

HWTEST_F(HostBindingTest, HandleDeviceStatusChanged_002, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    DeviceKey deviceKey = persistedStatus.hostDeviceKey;
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.hostDeviceStatus.isOnline = true;

    std::vector<DeviceStatus> emptyStatusList;
    binding->HandleDeviceStatusChanged(emptyStatusList);

    auto status = binding->GetStatus();
    EXPECT_FALSE(status.hostDeviceStatus.isOnline);
}

HWTEST_F(HostBindingTest, HandleHostDeviceStatusUpdate_001, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    DeviceKey deviceKey = persistedStatus.hostDeviceKey;
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    auto deviceStatus = MakeDeviceStatus(deviceKey, true);
    binding->HandleHostDeviceStatusUpdate(deviceStatus);

    auto status = binding->GetStatus();
    EXPECT_TRUE(status.hostDeviceStatus.isOnline);
    EXPECT_EQ("TestDevice", status.hostDeviceStatus.deviceName);
}

HWTEST_F(HostBindingTest, HandleHostDeviceOffline_001, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.hostDeviceStatus.isOnline = true;
    binding->status_.isTokenValid = true;

    binding->HandleHostDeviceOffline();

    EXPECT_FALSE(binding->GetStatus().hostDeviceStatus.isOnline);
    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, HandleHostDeviceOffline_002, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.hostDeviceStatus.isOnline = false;

    binding->HandleHostDeviceOffline();

    EXPECT_FALSE(binding->GetStatus().hostDeviceStatus.isOnline);
}

HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_001, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->HandleAuthMaintainActiveChanged(true);

    EXPECT_TRUE(binding->GetStatus().localAuthMaintainActive);
}

HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_002, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    LocalDeviceProfile profile;
    profile.hostBindingRevokeTokenOnInactive = true;
    ON_CALL(crossDeviceMgr, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.localAuthMaintainActive = true;
    binding->status_.isTokenValid = true;
    binding->status_.hostDeviceStatus.atlRevokeDelayMs = 0;

    binding->HandleAuthMaintainActiveChanged(false);

    EXPECT_FALSE(binding->GetStatus().localAuthMaintainActive);
    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_003, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.localAuthMaintainActive = true;

    binding->HandleAuthMaintainActiveChanged(true);

    EXPECT_TRUE(binding->GetStatus().localAuthMaintainActive);
}

HWTEST_F(HostBindingTest, SetTokenValid_001, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->SetTokenValid(true, "unknown");

    EXPECT_TRUE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, SetTokenValid_002, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    EXPECT_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillOnce(Return(nullptr));

    binding->status_.isTokenValid = true;
    binding->SetTokenValid(false, "unknown");

    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, SetTokenValid_003, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    EXPECT_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _))
        .WillOnce(Invoke([](UserId companionUserId, int32_t companionSubProfileId, const DeviceKey &hostDeviceKey,
                        const std::string &triggerReason) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, companionSubProfileId,
                hostDeviceKey, triggerReason);
        }));
    EXPECT_CALL(requestMgr, Start(_)).WillOnce(Return(false));

    binding->status_.isTokenValid = true;
    binding->SetTokenValid(false, "unknown");

    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, SetTokenValid_004, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    EXPECT_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _))
        .WillOnce(Invoke([](UserId companionUserId, int32_t companionSubProfileId, const DeviceKey &hostDeviceKey,
                        const std::string &triggerReason) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, companionSubProfileId,
                hostDeviceKey, triggerReason);
        }));
    EXPECT_CALL(requestMgr, Start(_)).WillOnce(Return(true));

    binding->status_.isTokenValid = true;
    binding->SetTokenValid(false, "unknown");

    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, SetTokenValid_005, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    auto resyncRequest = std::make_shared<MockIRequest>();
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->SetTokenValid(true, "unknown");

    RelativeTimer::GetInstance().ExecuteAll();

    EXPECT_TRUE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, Destructor_001, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(nullptr));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.isTokenValid = true;

    binding.reset();
}

// HandleAuthMaintainActiveChanged(true) triggers a resync to host
HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_TriggersResync, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    // Start with inactive so Initialize does not trigger resync
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(false));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));

    // TriggerResyncToHost calls CreateCompanionRequestResyncRequest; return a non-null mock
    auto resyncRequest = std::make_shared<MockIRequest>();
    EXPECT_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _))
        .WillOnce(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    EXPECT_CALL(requestMgr, Start(_)).WillOnce(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    // Becoming active triggers resync to host
    binding->HandleAuthMaintainActiveChanged(true);

    EXPECT_TRUE(binding->GetStatus().localAuthMaintainActive);
}

// HandleAuthMaintainActiveChanged with same state (true->true) does not trigger resync
HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_True_NoResync, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    // Initialize with active=true triggers resync once (false->true transition)
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    // Resync is triggered once during Initialize (false->true), but NOT on the subsequent same-state call
    auto resyncRequest = std::make_shared<MockIRequest>();
    EXPECT_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _))
        .WillOnce(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    EXPECT_CALL(requestMgr, Start(_)).WillOnce(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    // Same-state transition (true->true) should be a no-op, no additional resync
    binding->HandleAuthMaintainActiveChanged(true);

    EXPECT_TRUE(binding->GetStatus().localAuthMaintainActive);
}

// HandleAuthMaintainActiveChanged(false) also triggers a resync to host (true->false transition)
HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_False_TriggersResync, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    // Start with active so Initialize triggers resync (false->true)
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    LocalDeviceProfile profile;
    profile.hostBindingRevokeTokenOnInactive = false;
    ON_CALL(crossDeviceMgr, GetLocalDeviceProfile()).WillByDefault(Return(profile));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    // Two resyncs: one during Initialize (false->true), one on explicit true->false
    auto resyncRequest = std::make_shared<MockIRequest>();
    EXPECT_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _))
        .Times(2)
        .WillOnce(Return(resyncRequest))
        .WillOnce(Return(resyncRequest));

    auto &requestMgr = guard.GetRequestManager();
    EXPECT_CALL(requestMgr, Start(_))
        .Times(2)
        .WillOnce(Return(true))
        .WillOnce(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    // Becoming inactive also triggers resync to host
    binding->HandleAuthMaintainActiveChanged(false);

    EXPECT_FALSE(binding->GetStatus().localAuthMaintainActive);
}

// HostBinding propagates companionSubProfileId from persisted status
HWTEST_F(HostBindingTest, Create_PropagatesCompanionSubProfileId, TestSize.Level0)
{
    MockGuard guard;

    auto &crossDeviceMgr = guard.GetCrossDeviceCommManager();
    EXPECT_CALL(crossDeviceMgr, SubscribeDeviceStatus(_, _, _))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(crossDeviceMgr, SubscribeIsAuthMaintainActive(_))
        .Times(AtMost(1))
        .WillOnce(Return(ByMove(MakeSubscription())));
    ON_CALL(crossDeviceMgr, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
    ON_CALL(crossDeviceMgr, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
    ON_CALL(crossDeviceMgr, IsAuthMaintainActive()).WillByDefault(Return(true));

    auto &companionMgr = guard.GetCompanionManager();
    CompanionStatus mockCompanionStatus = {};
    mockCompanionStatus.templateId = UINT32_12345;
    mockCompanionStatus.hostUserId = INT32_100;
    mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
    mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
    mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
    mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
    mockCompanionStatus.isValid = true;
    mockCompanionStatus.tokenAuthAtl = std::nullopt;
    ON_CALL(companionMgr, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
    ON_CALL(companionMgr, SetCompanionTokenAuthAtl(_, _, _)).WillByDefault(Return(true));

    auto &requestFactory = guard.GetRequestFactory();
    ON_CALL(requestFactory, CreateCompanionRevokeTokenRequest(_, _, _, _)).WillByDefault(Return(nullptr));
    ON_CALL(requestFactory, CreateCompanionRequestResyncRequest(_, _)).WillByDefault(Return(nullptr));

    auto &requestMgr = guard.GetRequestManager();
    ON_CALL(requestMgr, Start(_)).WillByDefault(Return(true));

    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    persistedStatus.companionSubProfileId = 42;

    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    EXPECT_EQ(binding->GetCompanionSubProfileId(), 42);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
