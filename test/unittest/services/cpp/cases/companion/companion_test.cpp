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

#include "companion.h"
#include "companion_manager_impl.h"
#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_comm_manager.h"
#include "mock_security_agent.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// Test constants
constexpr TemplateId TEMPLATE_ID_12345 = 12345;
constexpr UserId USER_ID_100 = 100;
constexpr UserId USER_ID_200 = 200;
constexpr BusinessId BUSINESS_ID_1 = static_cast<BusinessId>(1);
constexpr BusinessId BUSINESS_ID_2 = static_cast<BusinessId>(2);
constexpr BusinessId BUSINESS_ID_3 = static_cast<BusinessId>(3);
constexpr BusinessId BUSINESS_ID_4 = static_cast<BusinessId>(4);
constexpr BusinessId BUSINESS_ID_5 = static_cast<BusinessId>(5);
constexpr int32_t INT32_1 = 1;
constexpr int32_t INT32_3 = 3;

std::unique_ptr<Subscription> MakeSubscription()
{
    return std::make_unique<Subscription>([]() {});
}

PersistedCompanionStatus MakePersistedStatus(TemplateId templateId, UserId hostUserId, const std::string &deviceId,
    UserId deviceUserId)
{
    PersistedCompanionStatus status;
    status.templateId = templateId;
    status.hostUserId = hostUserId;
    status.companionDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    status.companionDeviceKey.deviceId = deviceId;
    status.companionDeviceKey.deviceUserId = deviceUserId;
    status.isValid = true;
    status.enabledBusinessIds = { BUSINESS_ID_1, BUSINESS_ID_2 };
    status.addedTime = 0;
    status.secureProtocolId = SecureProtocolId::DEFAULT;
    status.deviceModelInfo = "TestModel";
    status.deviceUserName = "TestUser";
    status.deviceName = "TestDevice";
    return status;
}

DeviceStatus MakeDeviceStatus(const DeviceKey &deviceKey, bool isOnline = true, bool isAuthMaintainActive = true)
{
    DeviceStatus status;
    status.deviceKey = deviceKey;
    status.isOnline = isOnline;
    status.isAuthMaintainActive = isAuthMaintainActive;
    status.deviceName = "TestDevice";
    status.deviceUserName = "TestUser";
    status.deviceModelInfo = "TestModel";
    status.protocolId = ProtocolId::VERSION_1;
    status.secureProtocolId = SecureProtocolId::DEFAULT;
    return status;
}

class CompanionTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        mockCompanionManager_ = std::make_shared<MockCompanionManagerImpl>();

        ON_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
        ON_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillByDefault(Return());
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

    class MockCompanionManagerImpl : public CompanionManagerImpl {
    public:
        MOCK_METHOD(void, NotifyCompanionStatusChange, (), (override));
    };

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    std::shared_ptr<MockCompanionManagerImpl> mockCompanionManager_;
};

HWTEST_F(CompanionTest, Create_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::nullopt));

    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);

    EXPECT_NE(nullptr, companion);
    EXPECT_EQ(TEMPLATE_ID_12345, companion->GetTemplateId());
    EXPECT_EQ(USER_ID_100, companion->GetHostUserId());
    EXPECT_EQ("test_device_id", companion->GetCompanionDeviceKey().deviceId);
}

HWTEST_F(CompanionTest, Create_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;

    auto deviceStatus = MakeDeviceStatus(deviceKey);
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(ByMove(MakeSubscription())));

    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);

    ASSERT_NE(nullptr, companion);
    auto status = companion->GetStatus();
    EXPECT_TRUE(status.companionDeviceStatus.isOnline);
    EXPECT_TRUE(status.companionDeviceStatus.isAuthMaintainActive);
}

HWTEST_F(CompanionTest, Create_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(nullptr));

    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);

    EXPECT_EQ(nullptr, companion);
}

HWTEST_F(CompanionTest, HandleDeviceStatusChanged_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    auto deviceStatus = MakeDeviceStatus(deviceKey, true, true);
    std::vector<DeviceStatus> statusList { deviceStatus };
    companion->HandleDeviceStatusChanged(statusList);

    auto status = companion->GetStatus();
    EXPECT_TRUE(status.companionDeviceStatus.isOnline);
    EXPECT_TRUE(status.companionDeviceStatus.isAuthMaintainActive);
}

HWTEST_F(CompanionTest, HandleDeviceStatusChanged_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    std::vector<DeviceStatus> emptyStatusList;
    companion->HandleDeviceStatusChanged(emptyStatusList);

    auto status = companion->GetStatus();
    EXPECT_FALSE(status.companionDeviceStatus.isOnline);
}

HWTEST_F(CompanionTest, HandleDeviceStatusUpdate_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    companion->HandleDeviceStatusUpdate(deviceStatus);

    auto status = companion->GetStatus();
    EXPECT_TRUE(status.companionDeviceStatus.isOnline);
    EXPECT_FALSE(status.companionDeviceStatus.isAuthMaintainActive);
    EXPECT_FALSE(status.tokenAtl.has_value());
}

HWTEST_F(CompanionTest, HandleDeviceStatusUpdate_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    companion->status_.companionDeviceStatus = deviceStatus;
    companion->HandleDeviceStatusUpdate(deviceStatus);
}

HWTEST_F(CompanionTest, HandleDeviceOffline_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->status_.companionDeviceStatus.isOnline = true;
    companion->HandleDeviceOffline();

    EXPECT_FALSE(companion->GetStatus().companionDeviceStatus.isOnline);
}

HWTEST_F(CompanionTest, SetEnabledBusinessIds_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    std::vector<BusinessId> newBusinessIds = { BUSINESS_ID_3, BUSINESS_ID_4, BUSINESS_ID_5 };

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->SetEnabledBusinessIds(newBusinessIds);

    // Compare the vectors by checking size and elements
    const auto &statusBusinessIds = companion->GetStatus().enabledBusinessIds;
    EXPECT_EQ(newBusinessIds.size(), statusBusinessIds.size());
    for (size_t i = 0; i < newBusinessIds.size() && i < statusBusinessIds.size(); ++i) {
        EXPECT_EQ(newBusinessIds[i], statusBusinessIds[i]);
    }
}

HWTEST_F(CompanionTest, SetEnabledBusinessIds_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    std::vector<BusinessId> sameBusinessIds = { BUSINESS_ID_1, BUSINESS_ID_2 };
    companion->SetEnabledBusinessIds(sameBusinessIds);
}

HWTEST_F(CompanionTest, SetCompanionValid_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->SetCompanionValid(false);

    EXPECT_FALSE(companion->GetStatus().isValid);
}

HWTEST_F(CompanionTest, SetCompanionValid_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);

    ASSERT_NE(nullptr, companion);

    companion->SetCompanionValid(true);
    EXPECT_TRUE(companion->GetStatus().isValid);
}

HWTEST_F(CompanionTest, SetCompanionTokenAtl_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAtl(INT32_3);

    auto status = companion->GetStatus();
    ASSERT_TRUE(status.tokenAtl.has_value());
    EXPECT_EQ(INT32_3, status.tokenAtl.value());
}

HWTEST_F(CompanionTest, SetCompanionTokenAtl_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    companion->status_.tokenAtl = INT32_1;
    companion->SetCompanionTokenAtl(std::nullopt);

    EXPECT_FALSE(companion->GetStatus().tokenAtl.has_value());
}

HWTEST_F(CompanionTest, SetCompanionTokenAtl_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAtl(INT32_3);

    RelativeTimer::GetInstance().ExecuteAll();

    EXPECT_FALSE(companion->GetStatus().tokenAtl.has_value());
}

HWTEST_F(CompanionTest, SetDeviceNames_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->SetDeviceNames("NewDevice", "NewUser");

    auto status = companion->GetStatus();
    EXPECT_EQ("NewDevice", status.companionDeviceStatus.deviceName);
    EXPECT_EQ("NewUser", status.companionDeviceStatus.deviceUserName);
}

HWTEST_F(CompanionTest, SetDeviceNames_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetDeviceNames("TestDevice", "TestUser");
}

HWTEST_F(CompanionTest, SetDeviceNames_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->SetDeviceNames("NewDevice", "TestUser");

    auto status = companion->GetStatus();
    EXPECT_EQ("NewDevice", status.companionDeviceStatus.deviceName);
    EXPECT_EQ("TestUser", status.companionDeviceStatus.deviceUserName);
}

HWTEST_F(CompanionTest, SetDeviceNames_004, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->SetDeviceNames("TestDevice", "NewUser");

    auto status = companion->GetStatus();
    EXPECT_EQ("TestDevice", status.companionDeviceStatus.deviceName);
    EXPECT_EQ("NewUser", status.companionDeviceStatus.deviceUserName);
}

HWTEST_F(CompanionTest, NotifySubscribersManagerNull, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    std::weak_ptr<CompanionManagerImpl> nullWeakPtr;
    auto companion = std::make_shared<Companion>(persistedStatus, nullWeakPtr);

    EXPECT_NO_THROW(companion->NotifySubscribers());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
