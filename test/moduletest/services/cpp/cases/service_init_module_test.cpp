/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "iam_logger.h"
#include "module_test_guard.h"
#include "relative_timer.h"
#include "service_common.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA_MODULE_TEST"

using namespace testing;
using namespace testing::ext;

class ServiceInitModuleTest : public testing::Test {};

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// ============================================================================
// Test 1: Service init — production pipeline completes, singletons queryable
// ============================================================================
//
// What this tests:
//   ModuleTestGuard → BaseServiceInitializer 19-step init pipeline (all production code)
//   → All singletons registered, adapters injected, channels wired
//   → Key interfaces return valid (empty) results
//
// E2E level: HIGH
//   - Injection: TestServiceInitializer overrides virtual init methods to inject Fakes/Mocks
//   - Production path: all wiring, subscriptions, cross-references are real
//   - Verification: query production interfaces through global accessors
// ============================================================================
HWTEST_F(ServiceInitModuleTest, ServiceInitSucceedsE2E_001, TestSize.Level0)
{
    IAM_LOGI("[Phase] Setup — ModuleTestGuard initializes service via BaseServiceInitializer");
    ModuleTestGuard guard;

    IAM_LOGI("[Phase] Run — query production interfaces to verify singletons registered");
    // CommManager: started by BaseServiceInitializer, query succeeds
    auto deviceStatus = GetCrossDeviceCommManager().GetAllDeviceStatus();
    EXPECT_TRUE(deviceStatus.empty()); // no devices yet

    // CompanionManager: registered but empty
    auto companions = GetCompanionManager().GetAllCompanionStatus();
    EXPECT_TRUE(companions.empty());

    // HostBindingManager: registered — querying a nonexistent binding returns nullopt
    auto binding = GetHostBindingManager().GetHostBindingStatus(9999);
    EXPECT_FALSE(binding.has_value());
}

// ============================================================================
// Test 2: Active user switch → load persisted Companions + HostBindings
// ============================================================================
//
// What this tests:
//   FakeUserIdManager.TestSetActiveUser(100)
//     → CompanionManagerImpl::OnActiveUserKeyChanged(100)     [production]
//       → FakeIdmAdapter.GetUserTemplates(100)               [Fake]
//       → SecurityAgent.HostGetPersistedCompanionStatus      [Mock → returns 1 companion]
//       → CompanionManagerImpl.Reload(companions, templates) [production]
//     → HostBindingManagerImpl::OnActiveUserKeyChanged(100)   [production]
//       → SecurityAgent.CompanionGetPersistedHostBindingStatus [Mock → returns 1 binding]
//       → HostBinding::Create × N                            [production]
//       → HostBindingManagerImpl.AddBindingInternal          [production]
//
//   Then verify via production interfaces:
//     GetCompanionManager().GetCompanionStatus(templateId)           → data matches
//     GetCompanionManager().GetCompanionStatus(hostUserId, deviceKey) → data matches
//     GetHostBindingManager().GetHostBindingStatus(bindingId)       → data matches
//
// E2E level: HIGH
//   - Injection through SecurityAgent Mock (the external boundary)
//   - Full production pipeline: user switch → fetch → parse → store
//   - Verification through production query interfaces
// ============================================================================
struct PersistedSwitchData {
    UserId hostUser { 100 };
    UserId companionUser { 200 };
    TemplateId templateId { 10001 };
    BindingId bindingId { 5001 };
    PersistedCompanionStatus persistedCompanion;
    PersistedHostBindingStatus persistedBinding;
};

// Sets up SecurityAgent mocks + IDM templates so the user-switch pipeline
// (TestSetActiveUser → OnActiveUserKeyChanged → persist fetch) loads one
// persisted companion and one host binding.
PersistedSwitchData SetupPersistedUserSwitchMocks(ModuleTestGuard &guard)
{
    PersistedSwitchData data;

    // Reset to invalid user first. ModuleTestGuard::SetupDefaultValues() sets user
    // to 100 which already triggered OnActiveUserKeyChanged(100) with empty data. Reset to 0
    // to allow re-trigger with the mock data below.
    guard.GetUserIdManager().TestSetActiveUser(0);
    guard.GetIdmAdapter().TestSetUserTemplates(data.hostUser, { data.templateId });

    data.persistedCompanion.templateId = data.templateId;
    data.persistedCompanion.hostUserKey.userId = data.hostUser;
    data.persistedCompanion.companionDeviceKey = MakeDeviceKey("companion-001", data.companionUser);
    data.persistedCompanion.isValid = true;
    data.persistedCompanion.enabledBusinessIds = { BusinessId::DEFAULT };
    data.persistedCompanion.deviceUserName = "Alice";

    // SecurityAgent returns 1 persisted companion. Using WillRepeatedly because production
    // code may invoke HostGetPersistedCompanionStatus multiple times during a single user
    // switch cycle (e.g., for different data categories).
    HostGetPersistedCompanionStatusOutput companionOutput = { .companionStatusList = { data.persistedCompanion } };
    EXPECT_CALL(guard.GetSecurityAgent(), HostGetPersistedCompanionStatus(_, _))
        .Times(testing::AnyNumber())
        .WillRepeatedly(DoAll(SetArgReferee<1>(companionOutput), Return(ResultCode::SUCCESS)));

    data.persistedBinding.bindingId = data.bindingId;
    data.persistedBinding.companionUserKey.userId = data.companionUser;
    data.persistedBinding.hostDeviceKey = MakeDeviceKey("host-001", data.hostUser);
    data.persistedBinding.isTokenValid = true;

    CompanionGetPersistedHostBindingStatusOutput bindingOutput;
    bindingOutput.hostBindingStatusList = { data.persistedBinding };
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGetPersistedHostBindingStatus(_, _))
        .Times(testing::AnyNumber())
        .WillRepeatedly(DoAll(SetArgReferee<1>(bindingOutput), Return(ResultCode::SUCCESS)));

    return data;
}

HWTEST_F(ServiceInitModuleTest, LoadPersistedDataAfterUserSwitchE2E_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    PersistedSwitchData data = SetupPersistedUserSwitchMocks(guard);

    guard.GetUserIdManager().TestSetActiveUser(101);
    guard.GetUserIdManager().TestSetActiveUser(data.hostUser);
    TaskRunnerManager::GetInstance().EnsureAllTaskExecuted();
    RelativeTimer::GetInstance().DrainExpiredTasks();

    auto companion = GetCompanionManager().GetCompanionStatus(data.templateId);
    ASSERT_TRUE(companion.has_value());
    EXPECT_EQ(companion->templateId, data.templateId);
    EXPECT_EQ(companion->hostUserKey.userId, data.hostUser);
    EXPECT_EQ(companion->companionDeviceStatus.deviceKey.deviceId, "companion-001");
    EXPECT_EQ(companion->enabledBusinessIds.size(), 1u);
    ASSERT_TRUE(GetCompanionManager()
            .GetCompanionStatus(UserKey { data.hostUser, INVALID_SUB_PROFILE_ID },
                data.persistedCompanion.companionDeviceKey)
            .has_value());
    EXPECT_EQ(GetCompanionManager().GetAllCompanionStatus().size(), 1u);

    auto binding = GetHostBindingManager().GetHostBindingStatus(data.bindingId);
    ASSERT_TRUE(binding.has_value());
    EXPECT_EQ(binding->bindingId, data.bindingId);
    auto bindingByDevice = GetHostBindingManager().GetHostBindingStatus(
        UserKey { data.companionUser, INVALID_SUB_PROFILE_ID }, data.persistedBinding.hostDeviceKey);
    ASSERT_TRUE(bindingByDevice.has_value());
    EXPECT_EQ(bindingByDevice->bindingId, data.bindingId);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
