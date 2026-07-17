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

#include "mock_cross_device_comm_manager.h"
#include "mock_security_agent.h"
#include "mock_time_keeper.h"

#include "adapter_manager.h"
#include "companion.h"
#include "companion_manager_impl.h"
#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

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
constexpr uint32_t TEST_ATL_REVOKE_DELAY_MS = 30000;
constexpr BusinessId BUSINESS_ID_3 = static_cast<BusinessId>(3);
constexpr BusinessId BUSINESS_ID_4 = static_cast<BusinessId>(4);
constexpr int32_t INT32_1 = 1;
constexpr BusinessId BUSINESS_ID_5 = static_cast<BusinessId>(5);
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
    status.deviceModelInfo = "TestModel";
    status.deviceUserName = "TestUser";
    status.deviceName = "TestDevice";
    return status;
}

DeviceStatus MakeDeviceStatus(const DeviceKey &deviceKey, bool isOnline = true, bool isAuthMaintainActive = true,
    std::optional<uint32_t> atlRevokeDelayMs = std::nullopt)
{
    DeviceStatus status;
    status.deviceKey = deviceKey;
    status.isOnline = isOnline;
    status.isAuthMaintainActive = isAuthMaintainActive;
    status.atlRevokeDelayMs = atlRevokeDelayMs;
    status.deviceName = "TestDevice";
    status.deviceUserName = "TestUser";
    status.deviceModelInfo = "TestModel";
    status.protocolId = ProtocolId::VERSION_1;
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

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        mockCompanionManager_ = std::make_shared<MockCompanionManagerImpl>();

        ON_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
        ON_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostUpdateCompanionStatus(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillByDefault(Return());
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

    class MockCompanionManagerImpl : public CompanionManagerImpl {
    public:
        MOCK_METHOD(void, NotifyCompanionStatusChange, (), (override));
        MOCK_METHOD(ResultCode, RemoveCompanion, (TemplateId templateId, bool removeHostBinding), (override));
    };

protected:
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    std::shared_ptr<MockCompanionManagerImpl> mockCompanionManager_;
};

HWTEST_F(CompanionTest, Create_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::nullopt));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);

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
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);

    ASSERT_NE(nullptr, companion);
    auto status = companion->GetStatus();
    EXPECT_TRUE(status.companionDeviceStatus.isOnline);
    EXPECT_TRUE(status.companionDeviceStatus.isAuthMaintainActive);
}

HWTEST_F(CompanionTest, Create_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _)).WillOnce(Return(nullptr));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);

    EXPECT_EQ(nullptr, companion);
}

HWTEST_F(CompanionTest, HandleDeviceStatusChanged_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
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
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
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
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    companion->HandleDeviceStatusUpdate(deviceStatus);

    auto status = companion->GetStatus();
    EXPECT_TRUE(status.companionDeviceStatus.isOnline);
    EXPECT_FALSE(status.companionDeviceStatus.isAuthMaintainActive);
    EXPECT_FALSE(status.tokenAuthAtl.has_value());
}

HWTEST_F(CompanionTest, HandleDeviceStatusUpdate_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    companion->status_.companionDeviceStatus = deviceStatus;
    companion->HandleDeviceStatusUpdate(deviceStatus);
}

HWTEST_F(CompanionTest, HandleDeviceStatusUpdate_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    // Business fields are unchanged, but a fresher sync time still counts as a status change.
    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    companion->status_.companionDeviceStatus = deviceStatus;
    EXPECT_EQ(companion->GetStatus().companionDeviceStatus.lastSyncTimeMs, 0u);

    deviceStatus.lastSyncTimeMs = 100;
    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());
    companion->HandleDeviceStatusUpdate(deviceStatus);

    // The adopted sync time is what lets isConfirmed go true downstream.
    EXPECT_EQ(companion->GetStatus().companionDeviceStatus.lastSyncTimeMs, 100u);
}

HWTEST_F(CompanionTest, HandleDeviceOffline_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->status_.companionDeviceStatus.isOnline = true;
    companion->HandleDeviceOffline();

    EXPECT_FALSE(companion->GetStatus().companionDeviceStatus.isOnline);
}

HWTEST_F(CompanionTest, SetEnabledBusinessIds_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
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
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    std::vector<BusinessId> sameBusinessIds = { BUSINESS_ID_1, BUSINESS_ID_2 };
    companion->SetEnabledBusinessIds(sameBusinessIds);
}

HWTEST_F(CompanionTest, SetCompanionValid_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->SetCompanionValid(false);

    EXPECT_FALSE(companion->GetStatus().isValid);
}

HWTEST_F(CompanionTest, SetCompanionValid_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);

    ASSERT_NE(nullptr, companion);

    companion->SetCompanionValid(true);
    EXPECT_TRUE(companion->GetStatus().isValid);
}

HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);

    auto status = companion->GetStatus();
    ASSERT_TRUE(status.tokenAuthAtl.has_value());
    EXPECT_EQ(INT32_3, status.tokenAuthAtl.value());
}

HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    // HostRevokeToken is called twice: once in SetCompanionTokenAuthAtl, once in destructor
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillRepeatedly(Return(ResultCode::SUCCESS));

    companion->status_.tokenAuthAtl = INT32_1;
    companion->SetCompanionTokenAuthAtl(std::nullopt);

    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);

    RelativeTimer::GetInstance().ExecuteAll();

    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

// --- HandleCompanionStatusChange tests ---

HWTEST_F(CompanionTest, HandleCompanionStatusChange_NoChange_NoUpdateCalled, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    // DeviceStatus has same deviceModelInfo/deviceName/deviceUserName as persisted status
    auto deviceStatus = MakeDeviceStatus(deviceKey, true, true);
    EXPECT_CALL(mockSecurityAgent_, HostUpdateCompanionStatus(_)).Times(0);
    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->HandleDeviceStatusUpdate(deviceStatus);

    auto status = companion->GetStatus();
    EXPECT_EQ("TestDevice", status.companionDeviceStatus.deviceName);
    EXPECT_EQ("TestUser", status.companionDeviceStatus.deviceUserName);
    EXPECT_EQ("TestModel", status.companionDeviceStatus.deviceModelInfo);
}

HWTEST_F(CompanionTest, HandleCompanionStatusChange_DeviceNameChanged_UpdateCalled, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    auto deviceStatus = MakeDeviceStatus(deviceKey, true, true);
    deviceStatus.deviceName = "NewDeviceName";
    EXPECT_CALL(mockSecurityAgent_, HostUpdateCompanionStatus(_)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->HandleDeviceStatusUpdate(deviceStatus);

    auto status = companion->GetStatus();
    EXPECT_EQ("NewDeviceName", status.companionDeviceStatus.deviceName);
}

HWTEST_F(CompanionTest, HandleCompanionStatusChange_ModelInfoChanged_UpdateCalled, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    auto deviceStatus = MakeDeviceStatus(deviceKey, true, true);
    deviceStatus.deviceModelInfo = "NewModelInfo";
    EXPECT_CALL(mockSecurityAgent_, HostUpdateCompanionStatus(_)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->HandleDeviceStatusUpdate(deviceStatus);

    auto status = companion->GetStatus();
    EXPECT_EQ("NewModelInfo", status.companionDeviceStatus.deviceModelInfo);
}

HWTEST_F(CompanionTest, HandleCompanionStatusChange_UpdateFailed_StatusStillUpdated, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    auto deviceStatus = MakeDeviceStatus(deviceKey, true, true);
    deviceStatus.deviceName = "NewDeviceName";
    EXPECT_CALL(mockSecurityAgent_, HostUpdateCompanionStatus(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));
    EXPECT_CALL(*mockCompanionManager_, NotifyCompanionStatusChange()).WillOnce(Return());

    companion->HandleDeviceStatusUpdate(deviceStatus);

    // Memory state updated even though persist failed
    auto status = companion->GetStatus();
    EXPECT_EQ("NewDeviceName", status.companionDeviceStatus.deviceName);
}

HWTEST_F(CompanionTest, NotifySubscribersManagerNull, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    std::weak_ptr<CompanionManagerImpl> nullWeakPtr;
    auto companion = std::make_shared<Companion>(persistedStatus, false, nullWeakPtr);

    EXPECT_NO_THROW(companion->NotifySubscribers());
}

HWTEST_F(CompanionTest, IsAddedToIdm_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, true, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_TRUE(companion->IsAddedToIdm());
}

HWTEST_F(CompanionTest, IsAddedToIdm_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_FALSE(companion->IsAddedToIdm());
}

HWTEST_F(CompanionTest, MarkAsAddedToIdm_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_FALSE(companion->IsAddedToIdm());

    companion->SetAddedToIdm(true);

    EXPECT_TRUE(companion->IsAddedToIdm());
}

HWTEST_F(CompanionTest, MarkAsAddedToIdm_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, true, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_TRUE(companion->IsAddedToIdm());

    companion->SetAddedToIdm(true);

    EXPECT_TRUE(companion->IsAddedToIdm());
}

HWTEST_F(CompanionTest, HandleTemplateAddToIdmTimeout_001, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, true, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_TRUE(companion->IsAddedToIdm());

    EXPECT_CALL(*mockCompanionManager_, RemoveCompanion(_, _)).Times(0);

    companion->HandleTemplateAddToIdmTimeout();
}

HWTEST_F(CompanionTest, HandleTemplateAddToIdmTimeout_002, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_FALSE(companion->IsAddedToIdm());

    EXPECT_CALL(*mockCompanionManager_, RemoveCompanion(TEMPLATE_ID_12345, _)).WillOnce(Return(ResultCode::SUCCESS));

    companion->HandleTemplateAddToIdmTimeout();
}

HWTEST_F(CompanionTest, HandleTemplateAddToIdmTimeout_003, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    EXPECT_FALSE(companion->IsAddedToIdm());

    std::weak_ptr<CompanionManagerImpl> nullWeakPtr;
    auto companionWithNullManager = std::make_shared<Companion>(persistedStatus, false, nullWeakPtr);

    EXPECT_CALL(*mockCompanionManager_, RemoveCompanion(_, _)).Times(0);

    companionWithNullManager->HandleTemplateAddToIdmTimeout();
}

// --- HandleAuthMaintainActiveChanged tests ---

HWTEST_F(CompanionTest, AuthMaintainInactive_AtlRevokeDelayNullopt_NoRevoke, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // First set authMaintain active (no delay configured yet)
    auto activeStatus = MakeDeviceStatus(deviceKey, true, true);
    companion->HandleDeviceStatusUpdate(activeStatus);
    ASSERT_TRUE(companion->GetStatus().companionDeviceStatus.isAuthMaintainActive);

    // atlRevokeDelayMs = nullopt, authMaintain goes inactive → no revoke
    auto inactiveStatus = MakeDeviceStatus(deviceKey, true, false);
    companion->HandleDeviceStatusUpdate(inactiveStatus);

    EXPECT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());
}

HWTEST_F(CompanionTest, AuthMaintainInactive_AtlRevokeDelayZero_ImmediateRevoke, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // First set authMaintain active with delay=0
    auto activeStatus = MakeDeviceStatus(deviceKey, true, true, 0);
    companion->HandleDeviceStatusUpdate(activeStatus);
    ASSERT_TRUE(companion->GetStatus().companionDeviceStatus.isAuthMaintainActive);

    // atlRevokeDelayMs = 0 → immediate revoke
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillRepeatedly(Return(ResultCode::SUCCESS));
    auto inactiveStatus = MakeDeviceStatus(deviceKey, true, false, 0);
    companion->HandleDeviceStatusUpdate(inactiveStatus);

    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

HWTEST_F(CompanionTest, AuthMaintainInactive_AtlRevokeDelayNonZero_TimerFiresAndRevokes, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // First set authMaintain active with delay=TEST_ATL_REVOKE_DELAY_MS
    auto activeStatus = MakeDeviceStatus(deviceKey, true, true, TEST_ATL_REVOKE_DELAY_MS);
    companion->HandleDeviceStatusUpdate(activeStatus);
    ASSERT_TRUE(companion->GetStatus().companionDeviceStatus.isAuthMaintainActive);

    // atlRevokeDelayMs = TEST_ATL_REVOKE_DELAY_MS → timer scheduled
    auto inactiveStatus = MakeDeviceStatus(deviceKey, true, false, TEST_ATL_REVOKE_DELAY_MS);
    companion->HandleDeviceStatusUpdate(inactiveStatus);

    // ATL still present before timer fires
    EXPECT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // Timer fires → ATL revoked
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillRepeatedly(Return(ResultCode::SUCCESS));
    RelativeTimer::GetInstance().ExecuteAll();

    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

HWTEST_F(CompanionTest, AuthMaintainInactive_TimerCancelledOnRecovery, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // First set authMaintain active
    auto activeStatus = MakeDeviceStatus(deviceKey, true, true, TEST_ATL_REVOKE_DELAY_MS);
    companion->HandleDeviceStatusUpdate(activeStatus);
    ASSERT_TRUE(companion->GetStatus().companionDeviceStatus.isAuthMaintainActive);

    // authMaintain goes inactive → timer scheduled
    auto inactiveStatus = MakeDeviceStatus(deviceKey, true, false, TEST_ATL_REVOKE_DELAY_MS);
    companion->HandleDeviceStatusUpdate(inactiveStatus);
    EXPECT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // authMaintain recovers before timer fires → timer cancelled, ATL preserved
    companion->HandleDeviceStatusUpdate(activeStatus);
    EXPECT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());
    // authMaintainInactiveTimer_ was cancelled, so only tokenTimeoutSubscription_ remains
    // (we do not call ExecuteAll here because the token timeout timer would also fire)
}

HWTEST_F(CompanionTest, AuthMaintainInactive_NoAtl_NoRevoke, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    // First set authMaintain active with delay
    auto activeStatus = MakeDeviceStatus(deviceKey, true, true, TEST_ATL_REVOKE_DELAY_MS);
    companion->HandleDeviceStatusUpdate(activeStatus);
    ASSERT_TRUE(companion->GetStatus().companionDeviceStatus.isAuthMaintainActive);

    // No ATL set, authMaintain goes inactive with delay → nothing happens
    auto inactiveStatus = MakeDeviceStatus(deviceKey, true, false, TEST_ATL_REVOKE_DELAY_MS);
    companion->HandleDeviceStatusUpdate(inactiveStatus);

    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
    RelativeTimer::GetInstance().ExecuteAll();
    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

HWTEST_F(CompanionTest, AuthMaintainInactive_DeviceOffline_CancelsTimer, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // Set online + authMaintain active with delay
    auto activeStatus = MakeDeviceStatus(deviceKey, true, true, TEST_ATL_REVOKE_DELAY_MS);
    companion->status_.companionDeviceStatus = activeStatus;

    // authMaintain goes inactive → timer scheduled
    auto inactiveStatus = MakeDeviceStatus(deviceKey, true, false, TEST_ATL_REVOKE_DELAY_MS);
    companion->HandleDeviceStatusUpdate(inactiveStatus);

    // Device offline → timer cancelled, ATL revoked
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillRepeatedly(Return(ResultCode::SUCCESS));
    companion->HandleDeviceOffline();

    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

HWTEST_F(CompanionTest, HandleDeviceOffline_WithAtl_RevokesToken, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;
    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    companion->status_.companionDeviceStatus.isOnline = true;

    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillRepeatedly(Return(ResultCode::SUCCESS));

    companion->HandleDeviceOffline();

    EXPECT_FALSE(companion->GetStatus().companionDeviceStatus.isOnline);
    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

// --- SetCompanionTokenAuthAtl with forEnrollment coverage ---

HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_EnrollmentWorn_NoNotWornTimer, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;

    // Device is online and worn at creation time
    auto deviceStatus = MakeDeviceStatus(deviceKey, true, true);
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);
    EXPECT_TRUE(companion->GetStatus().companionDeviceStatus.isAuthMaintainActive);

    // Set ATL with forEnrollment=true: not-worn timer should NOT be started because device IS worn
    companion->SetCompanionTokenAuthAtl(INT32_3, true);

    auto status = companion->GetStatus();
    ASSERT_TRUE(status.tokenAuthAtl.has_value());
    EXPECT_EQ(INT32_3, status.tokenAuthAtl.value());
}

HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_NotForEnrollment_NoNotWornTimer, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);

    // Device status defaults to offline/not-worn, but not-worn timer
    // should NOT be started because forEnrollment is false
    auto companion = Companion::Create(persistedStatus, true, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    companion->SetCompanionTokenAuthAtl(INT32_3);

    auto status = companion->GetStatus();
    ASSERT_TRUE(status.tokenAuthAtl.has_value());
    EXPECT_EQ(INT32_3, status.tokenAuthAtl.value());
}

// Core positive scenario: forEnrollment=true + device not worn -> timer starts
HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_EnrollmentNotWorn_StartsNotWornTimer, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;

    // Device is online but NOT worn at creation time
    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);
    EXPECT_FALSE(companion->GetStatus().companionDeviceStatus.isAuthMaintainActive);

    // Set ATL with forEnrollment=true + device not worn -> not-worn timer SHOULD be started
    companion->SetCompanionTokenAuthAtl(INT32_3, true);

    auto status = companion->GetStatus();
    ASSERT_TRUE(status.tokenAuthAtl.has_value());
    EXPECT_EQ(INT32_3, status.tokenAuthAtl.value());

    // ATL still present before timer fires
    EXPECT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());
}

// Timer fires -> token revoked + HostRevokeToken called
HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_EnrollmentNotWorn_TimerFiresAndRevokesToken, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;

    // Device is online but NOT worn
    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    // Set ATL with forEnrollment=true + device not worn -> not-worn timer started
    companion->SetCompanionTokenAuthAtl(INT32_3, true);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // Timer fires -> HostRevokeToken called and token cleared
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillRepeatedly(Return(ResultCode::SUCCESS));
    RelativeTimer::GetInstance().ExecuteAll();

    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

// Device worn recovery cancels enrollment timer
HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_EnrollmentNotWorn_TimerCancelledOnRecovery, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;

    // Device is online but NOT worn
    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    // Set ATL with forEnrollment=true + device not worn -> not-worn timer started
    companion->SetCompanionTokenAuthAtl(INT32_3, true);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // Device becomes worn -> authMaintainInactiveTimer_ cancelled
    auto wornStatus = MakeDeviceStatus(deviceKey, true, true);
    companion->HandleDeviceStatusUpdate(wornStatus);

    // Token should still be present (enrollment timer was cancelled)
    EXPECT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());
}

// Active token revocation (nullopt) cleans enrollment timer
HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_EnrollmentNotWorn_RevokedManually_CleansTimer, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;

    // Device is online but NOT worn
    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    // Set ATL with forEnrollment=true + device not worn -> not-worn timer started
    companion->SetCompanionTokenAuthAtl(INT32_3, true);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // Manually revoke token -> enrollment timer should be cleaned
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillRepeatedly(Return(ResultCode::SUCCESS));
    companion->SetCompanionTokenAuthAtl(std::nullopt);
    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());

    // ExecuteAll should not trigger any stale timer
    RelativeTimer::GetInstance().ExecuteAll();
    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

// Repeated SetCompanionTokenAuthAtl refreshes token, old enrollment timer still runs
HWTEST_F(CompanionTest, SetCompanionTokenAuthAtl_EnrollmentNotWorn_RefreshAtl_OldTimerStillRuns, TestSize.Level0)
{
    auto persistedStatus = MakePersistedStatus(TEMPLATE_ID_12345, USER_ID_100, "test_device_id", USER_ID_200);
    DeviceKey deviceKey = persistedStatus.companionDeviceKey;

    // Device is online but NOT worn
    auto deviceStatus = MakeDeviceStatus(deviceKey, true, false);
    EXPECT_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillOnce(Return(std::make_optional(deviceStatus)));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _, _))
        .WillOnce(Return(ByMove(MakeSubscription())));

    auto companion = Companion::Create(persistedStatus, false, mockCompanionManager_);
    ASSERT_NE(nullptr, companion);

    // Set ATL with forEnrollment=true + device not worn -> not-worn timer started
    companion->SetCompanionTokenAuthAtl(INT32_3, true);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());

    // Token refreshed with forEnrollment=false (e.g. obtain_token path)
    companion->SetCompanionTokenAuthAtl(INT32_1, false);
    ASSERT_TRUE(companion->GetStatus().tokenAuthAtl.has_value());
    EXPECT_EQ(INT32_1, companion->GetStatus().tokenAuthAtl.value());

    // Enrollment timer fires -> token revoked (old timer was NOT cancelled by refresh)
    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillRepeatedly(Return(ResultCode::SUCCESS));
    RelativeTimer::GetInstance().ExecuteAll();

    EXPECT_FALSE(companion->GetStatus().tokenAuthAtl.has_value());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
