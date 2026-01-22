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
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "attributes.h"
#include "companion_device_auth_all_in_one_executor.h"
#include "fwk_common.h"
#include "host_add_companion_request.h"
#include "host_mix_auth_request.h"
#include "relative_timer.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "user_id_manager.h"

#include "adapter_manager.h"
#include "mock_companion_manager.h"
#include "mock_host_binding_manager.h"
#include "mock_misc_manager.h"
#include "mock_request_factory.h"
#include "mock_request_manager.h"
#include "mock_security_agent.h"
#include "mock_time_keeper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

const uint32_t ATTR_ROOT = 100000;
const uint32_t ATTR_TEMPLATE_ID_LIST = 100007;
const uint32_t ATTR_DATA = 100020;
const uint32_t ATTR_AUTH_TYPE = 100024;
const uint32_t ATTR_USER_ID = 100041;
const uint32_t ATTR_LOCK_STATE_AUTH_TYPE = 100075;
constexpr int32_t INT32_100 = 100;
constexpr uint64_t UINT64_123 = 123;
constexpr uint64_t UINT64_456 = 456;
constexpr uint64_t UINT64_12345 = 12345;

class FakeUserIdManager : public IUserIdManager {
public:
    bool Initialize() override
    {
        return true;
    }

    int32_t GetActiveUserId() const override
    {
        return activeUserId_;
    }

    std::string GetActiveUserName() const override
    {
        return "tester";
    }

    std::unique_ptr<Subscription> SubscribeActiveUserId(ActiveUserIdCallback &&callback) override
    {
        activeUserIdCallback_ = std::move(callback);
        return std::make_unique<Subscription>([]() {});
    }

    bool IsUserIdValid(int32_t userId) override
    {
        return userId == activeUserId_;
    }

private:
    int32_t activeUserId_ { INT32_100 };
    ActiveUserIdCallback activeUserIdCallback_ {};
};

class MockFwkExecuteCallback : public FwkIExecuteCallback {
public:
    MOCK_METHOD(void, OnResult, (FwkResultCode result, const std::vector<uint8_t> &extraInfo), (override));
    MOCK_METHOD(void, OnResult, (FwkResultCode result), (override));
    MOCK_METHOD(void, OnAcquireInfo, (int32_t acquire, const std::vector<uint8_t> &extraInfo), (override));
    MOCK_METHOD(void, OnMessage, (int destRole, const std::vector<uint8_t> &msg), (override));
};

class CompanionDeviceAuthAllInOneExecutorTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto securityAgent = std::shared_ptr<ISecurityAgent>(&mockSecurityAgent_, [](ISecurityAgent *) {});
        SingletonManager::GetInstance().SetSecurityAgent(securityAgent);

        auto requestFactory = std::shared_ptr<IRequestFactory>(&mockRequestFactory_, [](IRequestFactory *) {});
        SingletonManager::GetInstance().SetRequestFactory(requestFactory);

        auto requestManager = std::shared_ptr<IRequestManager>(&mockRequestManager_, [](IRequestManager *) {});
        SingletonManager::GetInstance().SetRequestManager(requestManager);

        auto companionManager = std::shared_ptr<ICompanionManager>(&mockCompanionManager_, [](ICompanionManager *) {});
        SingletonManager::GetInstance().SetCompanionManager(companionManager);

        auto hostBindingManager =
            std::shared_ptr<IHostBindingManager>(&mockHostBindingManager_, [](IHostBindingManager *) {});
        SingletonManager::GetInstance().SetHostBindingManager(hostBindingManager);

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto activeUserIdMgr = std::make_shared<FakeUserIdManager>();
        SingletonManager::GetInstance().SetUserIdManager(activeUserIdMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        uint32_t maxTemplateAcl = 3;
        ON_CALL(mockSecurityAgent_, HostGetExecutorInfo(_))
            .WillByDefault(Invoke([maxTemplateAcl](HostGetExecutorInfoOutput &output) {
                output.executorInfo.esl = 1;
                output.executorInfo.maxTemplateAcl = maxTemplateAcl;
                output.executorInfo.publicKey = { 1, 2, 3 };
                return ResultCode::SUCCESS;
            }));
        ON_CALL(mockSecurityAgent_, HostOnRegisterFinish(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockSecurityAgent_, CompanionRevokeToken(_)).WillByDefault(Return(ResultCode::SUCCESS));
        ON_CALL(mockRequestManager_, Start(_)).WillByDefault(Return(true));
        ON_CALL(mockRequestManager_, CancelRequestByScheduleId(_)).WillByDefault(Return(true));
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    NiceMock<MockSecurityAgent> mockSecurityAgent_;
    NiceMock<MockRequestFactory> mockRequestFactory_;
    NiceMock<MockRequestManager> mockRequestManager_;
    NiceMock<MockCompanionManager> mockCompanionManager_;
    NiceMock<MockHostBindingManager> mockHostBindingManager_;
    NiceMock<MockMiscManager> mockMiscManager_;
};

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Constructor_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    EXPECT_NE(nullptr, executor);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, GetExecutorInfo_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkExecutorInfo info;
    FwkResultCode ret = executor->GetExecutorInfo(info);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
    EXPECT_EQ(UserAuth::AuthType::COMPANION_DEVICE, info.authType);
    EXPECT_EQ(UserAuth::ExecutorRole::ALL_IN_ONE, info.executorRole);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, GetExecutorInfo_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    EXPECT_CALL(mockSecurityAgent_, HostGetExecutorInfo(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    FwkExecutorInfo info;
    FwkResultCode ret = executor->GetExecutorInfo(info);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, GetExecutorInfo_003, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);
    executor->inner_ = nullptr;

    FwkExecutorInfo info;
    FwkResultCode ret = executor->GetExecutorInfo(info);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, OnRegisterFinish_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };
    std::vector<uint8_t> frameworkPublicKey = { 1, 2, 3 };
    std::vector<uint8_t> extraInfo = { 4, 5, 6 };

    EXPECT_CALL(mockSecurityAgent_, HostOnRegisterFinish(_)).WillOnce(Return(ResultCode::SUCCESS));

    FwkResultCode ret = executor->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, OnRegisterFinish_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey;
    std::vector<uint8_t> extraInfo;

    EXPECT_CALL(mockSecurityAgent_, HostOnRegisterFinish(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    FwkResultCode ret = executor->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, OnRegisterFinish_003, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);
    executor->inner_ = nullptr;

    std::vector<uint64_t> templateIdList;
    std::vector<uint8_t> frameworkPublicKey;
    std::vector<uint8_t> extraInfo;

    FwkResultCode ret = executor->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, SendMessage_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    int32_t srcRole = 1;
    std::vector<uint8_t> msg = { 1, 2, 3 };

    FwkResultCode ret = executor->SendMessage(scheduleId, srcRole, msg);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, SendMessage_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);
    executor->inner_ = nullptr;

    uint64_t scheduleId = UINT64_12345;
    int32_t srcRole = 1;
    std::vector<uint8_t> msg = { 1, 2, 3 };

    FwkResultCode ret = executor->SendMessage(scheduleId, srcRole, msg);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Enroll_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkEnrollParam param;
    param.extraInfo = { 1, 2, 3 };
    param.tokenId = INT32_100;

    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    EXPECT_CALL(mockRequestFactory_, CreateHostAddCompanionRequest(_, _, _, _))
        .WillOnce(Invoke([](ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg, uint32_t tokenId,
                             FwkResultCallback &&requestCallback) {
            return std::make_shared<HostAddCompanionRequest>(scheduleId, fwkMsg, tokenId, std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true));

    FwkResultCode ret = executor->Enroll(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Enroll_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkEnrollParam param;

    FwkResultCode ret = executor->Enroll(scheduleId, param, nullptr);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Enroll_003, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkEnrollParam param;

    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    EXPECT_CALL(mockRequestFactory_, CreateHostAddCompanionRequest(_, _, _, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(*callback, OnResult(FwkResultCode::GENERAL_ERROR, _)).Times(1);

    FwkResultCode ret = executor->Enroll(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Enroll_004, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkEnrollParam param;

    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    EXPECT_CALL(mockRequestFactory_, CreateHostAddCompanionRequest(_, _, _, _))
        .WillOnce(Invoke([](ScheduleId scheduleId, const std::vector<uint8_t> &fwkMsg, uint32_t tokenId,
                             FwkResultCallback &&requestCallback) {
            return std::make_shared<HostAddCompanionRequest>(scheduleId, fwkMsg, tokenId, std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));
    EXPECT_CALL(*callback, OnResult(FwkResultCode::GENERAL_ERROR, _)).Times(1);

    FwkResultCode ret = executor->Enroll(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Enroll_005, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);
    executor->inner_ = nullptr;

    uint64_t scheduleId = UINT64_12345;
    FwkEnrollParam param;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    FwkResultCode ret = executor->Enroll(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Authenticate_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkAuthenticateParam param;
    param.extraInfo = { 1, 2, 3 };
    param.userId = INT32_100;
    param.templateIdList = { 123, 456 };

    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    EXPECT_CALL(mockRequestFactory_, CreateHostMixAuthRequest(_, _, _, _, _))
        .WillOnce(Invoke([](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                             std::vector<TemplateId> templateIdList, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateIdList,
                std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(true));

    FwkResultCode ret = executor->Authenticate(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Authenticate_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkAuthenticateParam param;

    FwkResultCode ret = executor->Authenticate(scheduleId, param, nullptr);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Authenticate_003, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkAuthenticateParam param;
    param.userId = INT32_100;
    param.templateIdList = {};

    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    FwkResultCode ret = executor->Authenticate(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Authenticate_004, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkAuthenticateParam param;
    param.templateIdList = { 123 };

    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    EXPECT_CALL(mockRequestFactory_, CreateHostMixAuthRequest(_, _, _, _, _)).WillOnce(Return(nullptr));
    EXPECT_CALL(*callback, OnResult(FwkResultCode::GENERAL_ERROR, _)).Times(1);

    FwkResultCode ret = executor->Authenticate(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Authenticate_005, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    uint64_t scheduleId = UINT64_12345;
    FwkAuthenticateParam param;
    param.templateIdList = { 123 };

    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    EXPECT_CALL(mockRequestFactory_, CreateHostMixAuthRequest(_, _, _, _, _))
        .WillOnce(Invoke([](ScheduleId scheduleId, std::vector<uint8_t> fwkMsg, UserId hostUserId,
                             std::vector<TemplateId> templateIdList, FwkResultCallback &&requestCallback) {
            return std::make_shared<HostMixAuthRequest>(scheduleId, fwkMsg, hostUserId, templateIdList,
                std::move(requestCallback));
        }));
    EXPECT_CALL(mockRequestManager_, Start(_)).WillOnce(Return(false));
    EXPECT_CALL(*callback, OnResult(FwkResultCode::GENERAL_ERROR, _)).Times(1);

    FwkResultCode ret = executor->Authenticate(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Authenticate_006, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);
    executor->inner_ = nullptr;

    uint64_t scheduleId = UINT64_12345;
    FwkAuthenticateParam param;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    FwkResultCode ret = executor->Authenticate(scheduleId, param, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Delete_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };

    EXPECT_CALL(mockCompanionManager_, RemoveCompanion(_)).Times(2).WillRepeatedly(Return(ResultCode::SUCCESS));

    FwkResultCode ret = executor->Delete(templateIdList);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Delete_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    std::vector<uint64_t> templateIdList = {};

    FwkResultCode ret = executor->Delete(templateIdList);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Delete_003, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    std::vector<uint64_t> templateIdList = { 123 };

    EXPECT_CALL(mockCompanionManager_, RemoveCompanion(_)).WillOnce(Return(ResultCode::GENERAL_ERROR));

    FwkResultCode ret = executor->Delete(templateIdList);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Delete_004, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);
    executor->inner_ = nullptr;

    std::vector<uint64_t> templateIdList = { 123 };

    FwkResultCode ret = executor->Delete(templateIdList);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Cancel_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    EXPECT_CALL(mockRequestManager_, CancelRequestByScheduleId(_)).WillOnce(Return(true));

    uint64_t scheduleId = UINT64_12345;
    FwkResultCode ret = executor->Cancel(scheduleId);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Cancel_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    EXPECT_CALL(mockRequestManager_, CancelRequestByScheduleId(_)).WillOnce(Return(false));

    uint64_t scheduleId = UINT64_12345;
    FwkResultCode ret = executor->Cancel(scheduleId);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, Cancel_003, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);
    executor->inner_ = nullptr;

    uint64_t scheduleId = UINT64_12345;
    FwkResultCode ret = executor->Cancel(scheduleId);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, SendCommand_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_GET;
    std::vector<uint8_t> extraInfo;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, SendCommand_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    std::vector<uint8_t> extraInfo;

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, nullptr);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, SendCommand_003, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_UNFREEZE;
    std::vector<uint8_t> extraInfo;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, SendCommand_004, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);
    executor->inner_ = nullptr;

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_GET;
    std::vector<uint8_t> extraInfo;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, GetProperty_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    std::vector<uint64_t> templateIdList;
    std::vector<FwkAttributeKey> keys;
    FwkProperty property;

    FwkResultCode ret = executor->GetProperty(templateIdList, keys, property);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, SetCachedTemplates_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    std::vector<uint64_t> templateIdList;

    FwkResultCode ret = executor->SetCachedTemplates(templateIdList);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_001, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    std::vector<uint8_t> extraInfo;

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_002, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes info;
    std::vector<uint8_t> rootTlv = { 1 };
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_003, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes dataTlvAttrs;
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::COMPANION_DEVICE));
    std::vector<uint8_t> dataTlv = dataTlvAttrs.Serialize();

    Attributes rootTlvAttrs;
    rootTlvAttrs.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    std::vector<uint8_t> rootTlv = rootTlvAttrs.Serialize();

    Attributes info;
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_004, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes dataTlvAttrs;
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::PIN));
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_LOCK_STATE_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::PIN));
    dataTlvAttrs.SetInt32Value(static_cast<Attributes::AttributeKey>(ATTR_USER_ID), INT32_100);
    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };
    dataTlvAttrs.SetUint64ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_TEMPLATE_ID_LIST), templateIdList);
    std::vector<uint8_t> dataTlv = dataTlvAttrs.Serialize();

    Attributes rootTlvAttrs;
    rootTlvAttrs.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    std::vector<uint8_t> rootTlv = rootTlvAttrs.Serialize();

    Attributes info;
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::GENERAL_ERROR, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_005, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes dataTlvAttrs;
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::COMPANION_DEVICE));
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_LOCK_STATE_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::FINGERPRINT));
    dataTlvAttrs.SetInt32Value(static_cast<Attributes::AttributeKey>(ATTR_USER_ID), INT32_100);
    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };
    dataTlvAttrs.SetUint64ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_TEMPLATE_ID_LIST), templateIdList);
    std::vector<uint8_t> dataTlv = dataTlvAttrs.Serialize();

    Attributes rootTlvAttrs;
    rootTlvAttrs.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    std::vector<uint8_t> rootTlv = rootTlvAttrs.Serialize();

    Attributes info;
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_006, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes dataTlvAttrs;
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::COMPANION_DEVICE));
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_LOCK_STATE_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::PIN));
    dataTlvAttrs.SetInt32Value(static_cast<Attributes::AttributeKey>(ATTR_USER_ID), INT32_100);
    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };
    dataTlvAttrs.SetUint64ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_TEMPLATE_ID_LIST), templateIdList);
    std::vector<uint8_t> dataTlv = dataTlvAttrs.Serialize();

    Attributes rootTlvAttrs;
    rootTlvAttrs.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    std::vector<uint8_t> rootTlv = rootTlvAttrs.Serialize();

    Attributes info;
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);
    EXPECT_CALL(mockCompanionManager_, SetCompanionTokenAtl(UINT64_123, testing::Eq(std::optional<Atl>()))).Times(1);
    EXPECT_CALL(mockCompanionManager_, SetCompanionTokenAtl(UINT64_456, testing::Eq(std::optional<Atl>()))).Times(1);
    EXPECT_CALL(mockHostBindingManager_, RevokeTokens(_)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_007, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_UNFREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes dataTlvAttrs;
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::COMPANION_DEVICE));
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_LOCK_STATE_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::PIN));
    dataTlvAttrs.SetInt32Value(static_cast<Attributes::AttributeKey>(ATTR_USER_ID), INT32_100);
    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };
    dataTlvAttrs.SetUint64ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_TEMPLATE_ID_LIST), templateIdList);
    std::vector<uint8_t> dataTlv = dataTlvAttrs.Serialize();

    Attributes rootTlvAttrs;
    rootTlvAttrs.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    std::vector<uint8_t> rootTlv = rootTlvAttrs.Serialize();

    Attributes info;
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);
    EXPECT_CALL(mockCompanionManager_, StartIssueTokenRequests(_, _)).Times(1);
    EXPECT_CALL(mockHostBindingManager_, StartObtainTokenRequests(_, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_008, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes dataTlvAttrs;
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::COMPANION_DEVICE));
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_LOCK_STATE_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::FACE));
    dataTlvAttrs.SetInt32Value(static_cast<Attributes::AttributeKey>(ATTR_USER_ID), INT32_100);
    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };
    dataTlvAttrs.SetUint64ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_TEMPLATE_ID_LIST), templateIdList);
    std::vector<uint8_t> dataTlv = dataTlvAttrs.Serialize();

    Attributes rootTlvAttrs;
    rootTlvAttrs.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    std::vector<uint8_t> rootTlv = rootTlvAttrs.Serialize();

    Attributes info;
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_009, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_UNFREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes dataTlvAttrs;
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::COMPANION_DEVICE));
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_LOCK_STATE_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::FACE));
    dataTlvAttrs.SetInt32Value(static_cast<Attributes::AttributeKey>(ATTR_USER_ID), INT32_100);
    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };
    dataTlvAttrs.SetUint64ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_TEMPLATE_ID_LIST), templateIdList);
    std::vector<uint8_t> dataTlv = dataTlvAttrs.Serialize();

    Attributes rootTlvAttrs;
    rootTlvAttrs.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    std::vector<uint8_t> rootTlv = rootTlvAttrs.Serialize();

    Attributes info;
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);
    EXPECT_CALL(mockCompanionManager_, StartIssueTokenRequests(_, _)).Times(1);
    EXPECT_CALL(mockHostBindingManager_, StartObtainTokenRequests(_, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

HWTEST_F(CompanionDeviceAuthAllInOneExecutorTest, HandleFreezeRelatedCommand_010, TestSize.Level0)
{
    auto executor = std::make_shared<CompanionDeviceAuthAllInOneExecutor>();
    ASSERT_NE(nullptr, executor);

    FwkPropertyMode commandId = FwkPropertyMode::PROPERTY_MODE_FREEZE;
    auto callback = std::make_shared<NiceMock<MockFwkExecuteCallback>>();

    Attributes dataTlvAttrs;
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_AUTH_TYPE),
        static_cast<uint32_t>(AuthType::COMPANION_DEVICE));
    dataTlvAttrs.SetUint32Value(static_cast<Attributes::AttributeKey>(ATTR_LOCK_STATE_AUTH_TYPE), 999);
    dataTlvAttrs.SetInt32Value(static_cast<Attributes::AttributeKey>(ATTR_USER_ID), INT32_100);
    std::vector<uint64_t> templateIdList = { UINT64_123, UINT64_456 };
    dataTlvAttrs.SetUint64ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_TEMPLATE_ID_LIST), templateIdList);
    std::vector<uint8_t> dataTlv = dataTlvAttrs.Serialize();

    Attributes rootTlvAttrs;
    rootTlvAttrs.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_DATA), dataTlv);
    std::vector<uint8_t> rootTlv = rootTlvAttrs.Serialize();

    Attributes info;
    info.SetUint8ArrayValue(static_cast<Attributes::AttributeKey>(ATTR_ROOT), rootTlv);
    std::vector<uint8_t> extraInfo = info.Serialize();

    EXPECT_CALL(*callback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    FwkResultCode ret = executor->SendCommand(commandId, extraInfo, callback);

    EXPECT_EQ(FwkResultCode::SUCCESS, ret);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
