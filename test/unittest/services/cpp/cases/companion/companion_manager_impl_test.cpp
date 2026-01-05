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

#include "companion_manager_impl.h"
#include "host_issue_token_request.h"
#include "host_remove_host_binding_request.h"
#include "host_sync_device_status_request.h"
#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#include "mock_cross_device_comm_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_user_id_manager.h"

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
    status.enabledBusinessIds = { 1, 2 };
    status.addedTime = 0;
    status.secureProtocolId = SecureProtocolId::DEFAULT;
    status.deviceModelInfo = "TestModel";
    status.deviceUserName = "TestUser";
    status.deviceName = "TestDevice";
    return status;
}

class CompanionManagerImplTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto activeUserMgr = std::shared_ptr<IUserIdManager>(&mockActiveUserIdManager_, [](IUserIdManager *) {});
        SingletonManager::GetInstance().SetActiveUserIdManager(activeUserMgr);

        auto crossDeviceCommMgr =
            std::shared_ptr<ICrossDeviceCommManager>(&mockCrossDeviceCommManager_, [](ICrossDeviceCommManager *) {});
        SingletonManager::GetInstance().SetCrossDeviceCommManager(crossDeviceCommMgr);

        auto requestMgr = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestMgr);

        auto requestFactory = std::shared_ptr<IRequestFactory>(&mockRequestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        ON_CALL(mockActiveUserIdManager_, SubscribeActiveUserId(_)).WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockActiveUserIdManager_, GetActiveUserId()).WillByDefault(Return(activeUserId_));
        ON_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _))
            .WillByDefault(Return(ByMove(MakeSubscription())));
        ON_CALL(mockCrossDeviceCommManager_, GetDeviceStatus(_)).WillByDefault(Return(std::nullopt));
        ON_CALL(mockSecurityAgent_, HostBeginAddCompanion(_, _))
            .WillByDefault(DoAll(Invoke([](const HostBeginAddCompanionInput &, HostBeginAddCompanionOutput &output) {
                output.addHostBindingRequest = { 1, 2, 3, 4 };
            }),
                Return(ResultCode::SUCCESS)));
        ON_CALL(mockSecurityAgent_, HostEndAddCompanion(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostRemoveCompanion(_, _)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostUpdateCompanionStatus(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostUpdateCompanionEnabledBusinessIds(_))
            .WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockRequestFactory_, CreateHostRemoveHostBindingRequest(_, _))
            .WillByDefault(Invoke([this](UserId hostUserId, const DeviceKey &companionDeviceKey) {
                return std::make_shared<HostRemoveHostBindingRequest>(hostUserId, companionDeviceKey);
            }));
        ON_CALL(mockRequestFactory_, CreateHostIssueTokenRequest(_, _, _))
            .WillByDefault(Invoke(
                [this](UserId hostUserId, TemplateId templateId, const std::vector<uint8_t> &fwkUnlockMsg) {
                    return std::make_shared<HostIssueTokenRequest>(hostUserId, templateId, fwkUnlockMsg);
                }));
        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
    }

protected:
    int32_t activeUserId_ = 100;
    NiceMock<MockUserIdManager> mockActiveUserIdManager_;
    NiceMock<MockCrossDeviceCommManager> mockCrossDeviceCommManager_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockMiscManager> mockMiscManager_;
};

HWTEST_F(CompanionManagerImplTest, Create_001, TestSize.Level0)
{
    EXPECT_CALL(mockActiveUserIdManager_, SubscribeActiveUserId(_)).WillOnce(Return(ByMove(MakeSubscription())));

    auto manager = CompanionManagerImpl::Create();
    EXPECT_NE(nullptr, manager);
}

HWTEST_F(CompanionManagerImplTest, Create_002, TestSize.Level0)
{
    EXPECT_CALL(mockActiveUserIdManager_, SubscribeActiveUserId(_)).WillOnce(Return(nullptr));

    auto manager = CompanionManagerImpl::Create();
    EXPECT_NE(nullptr, manager);
}

HWTEST_F(CompanionManagerImplTest, Initialize_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->Initialize();
}

HWTEST_F(CompanionManagerImplTest, Reload_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<PersistedCompanionStatus> emptyList;
    manager->Reload(emptyList);

    EXPECT_EQ(0u, manager->GetAllCompanionStatus().size());
}

HWTEST_F(CompanionManagerImplTest, Reload_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto status = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList = { status };
    manager->Reload(persistedList);

    EXPECT_EQ(1u, manager->GetAllCompanionStatus().size());
}

HWTEST_F(CompanionManagerImplTest, Reload_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(nullptr));

    auto status = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList = { status };
    manager->Reload(persistedList);

    EXPECT_EQ(0u, manager->GetAllCompanionStatus().size());
}

HWTEST_F(CompanionManagerImplTest, GetCompanionStatusByTemplateId_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    auto status = manager->GetCompanionStatus(12345);
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(12345, status->templateId);
    EXPECT_EQ(activeUserId_, status->hostUserId);
}

HWTEST_F(CompanionManagerImplTest, GetCompanionStatusByTemplateId_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto status = manager->GetCompanionStatus(12345);
    EXPECT_FALSE(status.has_value());
}

HWTEST_F(CompanionManagerImplTest, GetCompanionStatusByDeviceUser_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "device-1";
    deviceKey.deviceUserId = 200;

    auto status = manager->GetCompanionStatus(activeUserId_, deviceKey);
    ASSERT_TRUE(status.has_value());
    EXPECT_EQ(12345, status->templateId);
}

HWTEST_F(CompanionManagerImplTest, GetCompanionStatusByDeviceUser_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    DeviceKey deviceKey;
    deviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    deviceKey.deviceId = "device-1";
    deviceKey.deviceUserId = 200;

    auto status = manager->GetCompanionStatus(activeUserId_, deviceKey);
    EXPECT_FALSE(status.has_value());
}

HWTEST_F(CompanionManagerImplTest, SubscribeCompanionDeviceStatusChange_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeCompanionDeviceStatusChange(
        [&callbackInvoked](const std::vector<CompanionStatus> &statusList) {
            (void)statusList;
            callbackInvoked = true;
        });

    EXPECT_NE(subscription, nullptr);

    manager->NotifyCompanionStatusChange();
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(CompanionManagerImplTest, UnsubscribeCompanionDeviceStatusChange_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    bool callbackInvoked = false;
    auto subscription = manager->SubscribeCompanionDeviceStatusChange(
        [&callbackInvoked](const std::vector<CompanionStatus> &) { callbackInvoked = true; });

    manager->UnsubscribeCompanionDeviceStatusChange(1);

    manager->NotifyCompanionStatusChange();
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_FALSE(callbackInvoked);
}

HWTEST_F(CompanionManagerImplTest, BeginAddCompanion_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = INVALID_USER_ID;

    BeginAddCompanionParams params;
    std::vector<uint8_t> outRequest;
    ResultCode ret = manager->BeginAddCompanion(params, outRequest);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, BeginAddCompanion_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    BeginAddCompanionParams params;
    params.hostDeviceKey.deviceUserId = 999;
    std::vector<uint8_t> outRequest;
    ResultCode ret = manager->BeginAddCompanion(params, outRequest);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, BeginAddCompanion_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    EXPECT_CALL(mockSecurityAgent_, HostBeginAddCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    BeginAddCompanionParams params;
    params.requestId = 1;
    params.hostDeviceKey.deviceUserId = activeUserId_;
    std::vector<uint8_t> outRequest;
    ResultCode ret = manager->BeginAddCompanion(params, outRequest);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, BeginAddCompanion_004, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    EXPECT_CALL(mockSecurityAgent_, HostBeginAddCompanion(_, _))
        .WillOnce(DoAll(Invoke([](const HostBeginAddCompanionInput &, HostBeginAddCompanionOutput &output) {
            output.addHostBindingRequest.clear();
        }),
            Return(ResultCode::SUCCESS)));

    BeginAddCompanionParams params;
    params.requestId = 1;
    params.hostDeviceKey.deviceUserId = activeUserId_;
    std::vector<uint8_t> outRequest;
    ResultCode ret = manager->BeginAddCompanion(params, outRequest);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, BeginAddCompanion_005, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    EXPECT_CALL(mockSecurityAgent_, HostBeginAddCompanion(_, _))
        .WillOnce(DoAll(Invoke([](const HostBeginAddCompanionInput &, HostBeginAddCompanionOutput &output) {
            output.addHostBindingRequest = { 1, 2, 3, 4 };
        }),
            Return(ResultCode::SUCCESS)));

    BeginAddCompanionParams params;
    params.requestId = 1;
    params.hostDeviceKey.deviceUserId = activeUserId_;
    std::vector<uint8_t> outRequest;
    ResultCode ret = manager->BeginAddCompanion(params, outRequest);

    EXPECT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(CompanionManagerImplTest, EndAddCompanion_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = INVALID_USER_ID;

    PersistedCompanionStatus companionStatus;
    std::vector<uint8_t> reply;
    std::vector<uint8_t> outFwkMsg;
    std::vector<uint8_t> outTokenData;
    Atl outAtl;
    int32_t requestId = 1;
    EndAddCompanionInputParam inputParam;
    inputParam.requestId = requestId;
    inputParam.companionStatus = companionStatus;
    inputParam.secureProtocolId = SecureProtocolId::DEFAULT;
    inputParam.addHostBindingReply = reply;
    ResultCode ret =
        manager->EndAddCompanion(inputParam, outFwkMsg, outTokenData, outAtl);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, EndAddCompanion_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    PersistedCompanionStatus companionStatus;
    companionStatus.hostUserId = 999;
    std::vector<uint8_t> reply;
    std::vector<uint8_t> outFwkMsg;
    std::vector<uint8_t> outTokenData;
    Atl outAtl;
    int32_t requestId = 1;
    EndAddCompanionInputParam inputParam;
    inputParam.requestId = requestId;
    inputParam.companionStatus = companionStatus;
    inputParam.secureProtocolId = SecureProtocolId::DEFAULT;
    inputParam.addHostBindingReply = reply;
    ResultCode ret =
        manager->EndAddCompanion(inputParam, outFwkMsg, outTokenData, outAtl);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, EndAddCompanion_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    EXPECT_CALL(mockSecurityAgent_, HostEndAddCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    PersistedCompanionStatus companionStatus;
    companionStatus.hostUserId = activeUserId_;
    std::vector<uint8_t> reply;
    std::vector<uint8_t> outFwkMsg;
    std::vector<uint8_t> outTokenData;
    Atl outAtl;
    int32_t requestId = 1;
    EndAddCompanionInputParam inputParam;
    inputParam.requestId = requestId;
    inputParam.companionStatus = companionStatus;
    inputParam.secureProtocolId = SecureProtocolId::DEFAULT;
    inputParam.addHostBindingReply = reply;
    ResultCode ret =
        manager->EndAddCompanion(inputParam, outFwkMsg, outTokenData, outAtl);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, EndAddCompanion_004, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    PersistedCompanionStatus companionStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<uint8_t> reply;
    std::vector<uint8_t> outFwkMsg;
    std::vector<uint8_t> outTokenData;
    Atl outAtl;

    EXPECT_CALL(mockSecurityAgent_, HostEndAddCompanion(_, _))
        .WillOnce(DoAll(Invoke([](const HostEndAddCompanionInput &, HostEndAddCompanionOutput &output) {
            output.templateId = 12345;
            output.fwkMsg = { 5, 6, 7, 8 };
        }),
            Return(ResultCode::SUCCESS)));
    int32_t requestId = 1;
    EndAddCompanionInputParam inputParam;
    inputParam.requestId = requestId;
    inputParam.companionStatus = companionStatus;
    inputParam.secureProtocolId = SecureProtocolId::DEFAULT;
    inputParam.addHostBindingReply = reply;
    ResultCode ret =
        manager->EndAddCompanion(inputParam, outFwkMsg, outTokenData, outAtl);

    EXPECT_EQ(ret, ResultCode::SUCCESS);
    EXPECT_EQ(outFwkMsg.size(), 4u);
    EXPECT_TRUE(manager->GetCompanionStatus(12345).has_value());
}

HWTEST_F(CompanionManagerImplTest, EndAddCompanion_005, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    PersistedCompanionStatus companionStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<uint8_t> reply;
    std::vector<uint8_t> outFwkMsg;
    std::vector<uint8_t> outTokenData;
    Atl outAtl;

    EXPECT_CALL(mockSecurityAgent_, HostEndAddCompanion(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockCrossDeviceCommManager_, SubscribeDeviceStatus(_, _)).WillOnce(Return(nullptr));
    int32_t requestId = 1;
    EndAddCompanionInputParam inputParam;
    inputParam.requestId = requestId;
    inputParam.companionStatus = companionStatus;
    inputParam.secureProtocolId = SecureProtocolId::DEFAULT;
    inputParam.addHostBindingReply = reply;
    ResultCode ret =
        manager->EndAddCompanion(inputParam, outFwkMsg, outTokenData, outAtl);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, RemoveCompanion_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    EXPECT_CALL(mockSecurityAgent_, HostRemoveCompanion(_, _)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ResultCode ret = manager->RemoveCompanion(12345);
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, RemoveCompanion_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    EXPECT_CALL(mockSecurityAgent_, HostRemoveCompanion(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockRequestFactory_, CreateHostRemoveHostBindingRequest(_, _)).WillOnce(Return(nullptr));

    ResultCode ret = manager->RemoveCompanion(12345);

    EXPECT_EQ(ret, ResultCode::SUCCESS);
    EXPECT_FALSE(manager->GetCompanionStatus(12345).has_value());
}

HWTEST_F(CompanionManagerImplTest, RemoveCompanion_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    EXPECT_CALL(mockSecurityAgent_, HostRemoveCompanion(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockRequestFactory_, CreateHostRemoveHostBindingRequest(_, _))
        .WillOnce(Invoke([this](UserId hostUserId, const DeviceKey &companionDeviceKey) {
            return std::make_shared<HostRemoveHostBindingRequest>(hostUserId, companionDeviceKey);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));

    ResultCode ret = manager->RemoveCompanion(12345);

    EXPECT_EQ(ret, ResultCode::SUCCESS);
    EXPECT_FALSE(manager->GetCompanionStatus(12345).has_value());
}

HWTEST_F(CompanionManagerImplTest, RemoveCompanion_004, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    EXPECT_CALL(mockSecurityAgent_, HostRemoveCompanion(_, _)).WillOnce(Return(ResultCode::SUCCESS));
    EXPECT_CALL(mockRequestFactory_, CreateHostRemoveHostBindingRequest(_, _))
        .WillOnce(Invoke([this](UserId hostUserId, const DeviceKey &companionDeviceKey) {
            return std::make_shared<HostRemoveHostBindingRequest>(hostUserId, companionDeviceKey);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true));

    ResultCode ret = manager->RemoveCompanion(12345);

    EXPECT_EQ(ret, ResultCode::SUCCESS);
    EXPECT_FALSE(manager->GetCompanionStatus(12345).has_value());
}

HWTEST_F(CompanionManagerImplTest, UpdateCompanionStatus_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    ResultCode ret = manager->UpdateCompanionStatus(12345, "NewDevice", "NewUser");
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, UpdateCompanionStatus_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    EXPECT_CALL(mockSecurityAgent_, HostUpdateCompanionStatus(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    ResultCode ret = manager->UpdateCompanionStatus(12345, "NewDevice", "NewUser");
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, UpdateCompanionStatus_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    EXPECT_CALL(mockSecurityAgent_, HostUpdateCompanionStatus(_)).WillOnce(Return(ResultCode::SUCCESS));

    ResultCode ret = manager->UpdateCompanionStatus(12345, "NewDevice", "NewUser");
    EXPECT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(CompanionManagerImplTest, UpdateCompanionEnabledBusinessIds_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<int32_t> businessIds = { 1, 2, 3 };
    ResultCode ret = manager->UpdateCompanionEnabledBusinessIds(12345, businessIds);
    EXPECT_EQ(ret, ResultCode::NOT_ENROLLED);
}

HWTEST_F(CompanionManagerImplTest, UpdateCompanionEnabledBusinessIds_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    EXPECT_CALL(mockSecurityAgent_, HostUpdateCompanionEnabledBusinessIds(_))
        .WillOnce(Return(ResultCode::NOT_ENROLLED));

    std::vector<int32_t> businessIds = { 1, 2, 3 };
    ResultCode ret = manager->UpdateCompanionEnabledBusinessIds(12345, businessIds);
    EXPECT_EQ(ret, ResultCode::NOT_ENROLLED);
}

HWTEST_F(CompanionManagerImplTest, UpdateCompanionEnabledBusinessIds_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    EXPECT_CALL(mockSecurityAgent_, HostUpdateCompanionEnabledBusinessIds(_)).WillOnce(Return(ResultCode::SUCCESS));

    std::vector<int32_t> businessIds = { 1, 2, 3 };
    ResultCode ret = manager->UpdateCompanionEnabledBusinessIds(12345, businessIds);
    EXPECT_EQ(ret, ResultCode::SUCCESS);
}

HWTEST_F(CompanionManagerImplTest, SetCompanionTokenAtl_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    bool result = manager->SetCompanionTokenAtl(12345, std::nullopt);
    EXPECT_FALSE(result);
}

HWTEST_F(CompanionManagerImplTest, SetCompanionTokenAtl_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    bool result = manager->SetCompanionTokenAtl(12345, 3);
    EXPECT_TRUE(result);

    auto status = manager->GetCompanionStatus(12345);
    ASSERT_TRUE(status.has_value());
    ASSERT_TRUE(status->tokenAtl.has_value());
    EXPECT_EQ(status->tokenAtl.value(), 3);
}

HWTEST_F(CompanionManagerImplTest, HandleCompanionCheckFail_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    ResultCode ret = manager->HandleCompanionCheckFail(12345);
    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, HandleCompanionCheckFail_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    ResultCode ret = manager->HandleCompanionCheckFail(12345);
    EXPECT_EQ(ret, ResultCode::SUCCESS);

    auto status = manager->GetCompanionStatus(12345);
    ASSERT_TRUE(status.has_value());
    EXPECT_FALSE(status->isValid);
}

HWTEST_F(CompanionManagerImplTest, OnActiveUserIdChanged_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    manager->OnActiveUserIdChanged(activeUserId_);

    auto status = manager->GetCompanionStatus(12345);
    EXPECT_TRUE(status.has_value());
}

HWTEST_F(CompanionManagerImplTest, OnActiveUserIdChanged_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    manager->OnActiveUserIdChanged(200);

    EXPECT_FALSE(manager->GetCompanionStatus(12345).has_value());
    EXPECT_EQ(manager->hostUserId_, 200);
}

HWTEST_F(CompanionManagerImplTest, OnActiveUserIdChanged_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    manager->OnActiveUserIdChanged(INVALID_USER_ID);

    EXPECT_FALSE(manager->GetCompanionStatus(12345).has_value());
    EXPECT_EQ(manager->hostUserId_, INVALID_USER_ID);
}

HWTEST_F(CompanionManagerImplTest, AddCompanionInternal_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    ResultCode ret = manager->AddCompanionInternal(nullptr);

    EXPECT_EQ(ret, ResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionManagerImplTest, StartIssueTokenRequests_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<uint64_t> templateIds;
    std::vector<uint8_t> fwkMsg;

    manager->StartIssueTokenRequests(templateIds, fwkMsg);
}

HWTEST_F(CompanionManagerImplTest, StartIssueTokenRequests_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    std::vector<uint64_t> templateIds = { 1 };
    std::vector<uint8_t> fwkMsg;

    EXPECT_CALL(mockRequestFactory_, CreateHostIssueTokenRequest(_, _, _)).Times(0);

    manager->StartIssueTokenRequests(templateIds, fwkMsg);
}

HWTEST_F(CompanionManagerImplTest, StartIssueTokenRequests_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    persistedStatus.isValid = false;
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    std::vector<uint64_t> templateIds = { 12345 };
    std::vector<uint8_t> fwkMsg;

    EXPECT_CALL(mockRequestFactory_, CreateHostIssueTokenRequest(_, _, _)).Times(0);

    manager->StartIssueTokenRequests(templateIds, fwkMsg);
}

HWTEST_F(CompanionManagerImplTest, StartIssueTokenRequests_004, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    std::vector<uint64_t> templateIds = { 12345 };
    std::vector<uint8_t> fwkMsg;

    EXPECT_CALL(mockRequestFactory_, CreateHostIssueTokenRequest(_, _, _)).WillOnce(Return(nullptr));

    manager->StartIssueTokenRequests(templateIds, fwkMsg);
}

HWTEST_F(CompanionManagerImplTest, StartIssueTokenRequests_005, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    std::vector<uint64_t> templateIds = { 12345 };
    std::vector<uint8_t> fwkMsg;

    EXPECT_CALL(mockRequestFactory_, CreateHostIssueTokenRequest(_, _, _))
        .WillOnce(Invoke([this](UserId hostUserId, TemplateId templateId, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<HostIssueTokenRequest>(hostUserId, templateId, fwkUnlockMsg);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));

    manager->StartIssueTokenRequests(templateIds, fwkMsg);
}

HWTEST_F(CompanionManagerImplTest, StartIssueTokenRequests_006, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    std::vector<uint64_t> templateIds = { 12345 };
    std::vector<uint8_t> fwkMsg;

    EXPECT_CALL(mockRequestFactory_, CreateHostIssueTokenRequest(_, _, _))
        .WillOnce(Invoke([this](UserId hostUserId, TemplateId templateId, const std::vector<uint8_t> &fwkUnlockMsg) {
            return std::make_shared<HostIssueTokenRequest>(hostUserId, templateId, fwkUnlockMsg);
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true));

    manager->StartIssueTokenRequests(templateIds, fwkMsg);
}

HWTEST_F(CompanionManagerImplTest, RevokeTokens_001, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    std::vector<uint64_t> templateIds;
    manager->RevokeTokens(templateIds);
}

HWTEST_F(CompanionManagerImplTest, RevokeTokens_002, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    std::vector<uint64_t> templateIds = { 1 };

    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).Times(0);

    manager->RevokeTokens(templateIds);
}

HWTEST_F(CompanionManagerImplTest, RevokeTokens_003, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    std::vector<uint64_t> templateIds = { 12345 };

    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).Times(0);

    manager->RevokeTokens(templateIds);
}

HWTEST_F(CompanionManagerImplTest, RevokeTokens_004, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    manager->SetCompanionTokenAtl(12345, 3);

    std::vector<uint64_t> templateIds = { 12345 };

    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    manager->RevokeTokens(templateIds);
}

HWTEST_F(CompanionManagerImplTest, RevokeTokens_005, TestSize.Level0)
{
    auto manager = CompanionManagerImpl::Create();
    ASSERT_NE(nullptr, manager);

    manager->hostUserId_ = activeUserId_;

    auto persistedStatus = MakePersistedStatus(12345, activeUserId_, "device-1", 200);
    std::vector<PersistedCompanionStatus> persistedList { persistedStatus };
    manager->Reload(persistedList);

    manager->SetCompanionTokenAtl(12345, 3);

    std::vector<uint64_t> templateIds = { 12345 };

    EXPECT_CALL(mockSecurityAgent_, HostRevokeToken(_)).WillOnce(Return(ResultCode::SUCCESS));

    manager->RevokeTokens(templateIds);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
