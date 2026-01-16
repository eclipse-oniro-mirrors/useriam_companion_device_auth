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

#include "companion_revoke_token_request.h"
#include "host_binding.h"
#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_companion_manager.h"
#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"

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
    status.secureProtocolId = SecureProtocolId::DEFAULT;
    return status;
}

class HostBindingTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto requestFactory = std::shared_ptr<IRequestFactory>(&mockRequestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        ON_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
        ON_CALL(mockCrossDeviceCommManager_, GetAllDeviceStatus()).WillByDefault(Return(std::vector<DeviceStatus> {}));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeIsAuthMaintainActive(_))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, IsAuthMaintainActive()).WillByDefault(Return(true));
        CompanionStatus mockCompanionStatus = {};
        mockCompanionStatus.templateId = UINT32_12345;
        mockCompanionStatus.hostUserId = INT32_100;
        mockCompanionStatus.companionDeviceStatus.deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        mockCompanionStatus.companionDeviceStatus.deviceKey.deviceId = "test_device_id";
        mockCompanionStatus.companionDeviceStatus.deviceKey.deviceUserId = INT32_200;
        mockCompanionStatus.companionDeviceStatus.deviceName = "test_device";
        mockCompanionStatus.companionDeviceStatus.deviceUserName = "test_user";
        mockCompanionStatus.isValid = true;
        mockCompanionStatus.tokenAtl = std::nullopt;
        ON_CALL(mockCompanionManager_, GetCompanionStatus(_, _)).WillByDefault(Return(mockCompanionStatus));
        ON_CALL(mockCompanionManager_, SetCompanionTokenAtl(_, _)).WillByDefault(Return(true));
        ON_CALL(mockRequestFactory_, CreateCompanionRevokeTokenRequest(_, _)).WillByDefault(Return(nullptr));
        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockMiscManager> mockMiscManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
};

HWTEST_F(HostBindingTest, Create_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeIsAuthMaintainActive(_))
        .WillOnce(Return(ByMove(MakeSubscription())));

    auto binding = HostBinding::Create(persistedStatus);

    EXPECT_NE(nullptr, binding);
    EXPECT_EQ(UINT32_12345, binding->GetBindingId());
    EXPECT_EQ(INT32_100, binding->GetCompanionUserId());
    EXPECT_EQ("test_device_id", binding->GetHostDeviceKey().deviceId);
}

HWTEST_F(HostBindingTest, Create_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(nullptr));

    auto binding = HostBinding::Create(persistedStatus);

    EXPECT_EQ(nullptr, binding);
}

HWTEST_F(HostBindingTest, Create_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeIsAuthMaintainActive(_)).WillOnce(Return(nullptr));

    auto binding = HostBinding::Create(persistedStatus);

    EXPECT_EQ(nullptr, binding);
}

HWTEST_F(HostBindingTest, HandleDeviceStatusChanged_001, TestSize.Level0)
{
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
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.hostDeviceStatus.isOnline = false;

    binding->HandleHostDeviceOffline();

    EXPECT_FALSE(binding->GetStatus().hostDeviceStatus.isOnline);
}

HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->HandleAuthMaintainActiveChanged(true);

    EXPECT_TRUE(binding->GetStatus().localAuthMaintainActive);
}

HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.localAuthMaintainActive = true;
    binding->status_.isTokenValid = true;

    binding->HandleAuthMaintainActiveChanged(false);

    EXPECT_FALSE(binding->GetStatus().localAuthMaintainActive);
    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, HandleAuthMaintainActiveChanged_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.localAuthMaintainActive = true;

    binding->HandleAuthMaintainActiveChanged(true);

    EXPECT_TRUE(binding->GetStatus().localAuthMaintainActive);
}

HWTEST_F(HostBindingTest, SetTokenValid_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->SetTokenValid(true);

    EXPECT_TRUE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, SetTokenValid_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    EXPECT_CALL(mockRequestFactory_, CreateCompanionRevokeTokenRequest(_, _)).WillOnce(Return(nullptr));

    binding->status_.isTokenValid = true;
    binding->SetTokenValid(false);

    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, SetTokenValid_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    EXPECT_CALL(mockRequestFactory_, CreateCompanionRevokeTokenRequest(_, _))
        .WillOnce(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));

    binding->status_.isTokenValid = true;
    binding->SetTokenValid(false);

    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, SetTokenValid_004, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    EXPECT_CALL(mockRequestFactory_, CreateCompanionRevokeTokenRequest(_, _))
        .WillOnce(Invoke([](UserId companionUserId, const DeviceKey &hostDeviceKey) {
            return std::make_shared<CompanionRevokeTokenRequest>(companionUserId, hostDeviceKey);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true));

    binding->status_.isTokenValid = true;
    binding->SetTokenValid(false);

    EXPECT_FALSE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, SetTokenValid_005, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->SetTokenValid(true);

    RelativeTimer::GetInstance().ExecuteAll();

    EXPECT_TRUE(binding->GetStatus().isTokenValid);
}

HWTEST_F(HostBindingTest, Destructor_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(UINT32_12345, INT32_100, "test_device_id", INT32_200);
    auto binding = HostBinding::Create(persistedStatus);
    ASSERT_NE(nullptr, binding);

    binding->status_.isTokenValid = true;

    binding.reset();
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
