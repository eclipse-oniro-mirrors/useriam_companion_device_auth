/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include <vector>

#include "module_test_guard.h"
#include "module_test_helpers.h"

#include "access_token_kit.h"
#include "accesstoken_kit.h"
#include "cross_device_comm_manager.h"
#include "iam_logger.h"
#include "iipc_available_device_status_callback.h"
#include "iremote_object.h"

#define LOG_TAG "CDA_SA_MODULE_TEST"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// Minimal subscriber callback: only needs a distinct IRemoteObject identity for dedup/keying.
class FakeSubscriberCallback : public IIpcAvailableDeviceStatusCallback {
public:
    FakeSubscriberCallback() : remote_(sptr<Remote>::MakeSptr())
    {
    }
    ErrCode OnAvailableDeviceStatusChange(const std::vector<IpcDeviceStatus> &) override
    {
        return 0;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return remote_;
    }

private:
    class Remote : public IRemoteObject {
    public:
        Remote() : IRemoteObject(u"FakeSubscriberCallback")
        {
        }
        int32_t GetObjectRefCount() override
        {
            return 1;
        }
        int SendRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) override
        {
            return 0;
        }
        bool AddDeathRecipient(const sptr<DeathRecipient> &) override
        {
            return true;
        }
        bool RemoveDeathRecipient(const sptr<DeathRecipient> &) override
        {
            return true;
        }
        int Dump(int, const std::vector<std::u16string> &) override
        {
            return 0;
        }
    };
    sptr<Remote> remote_;
};

// MANAGE = SUBSCRIBE_MODE_ALL_DEVICES (a foreground HAP pins it); AUTH = SUBSCRIBE_MODE_SUBSCRIBED_ONLY.
bool IsManageMode()
{
    return GetCrossDeviceCommManager().GetSubscribeMode() == SUBSCRIBE_MODE_ALL_DEVICES;
}

class SubscribeModeModuleTest : public testing::Test {};

// HAP subscriber whose window is visible -> MANAGE.
HWTEST_F(SubscribeModeModuleTest, HapForeground_Manage_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr UserId USER = 100;

    auto cb = sptr<FakeSubscriberCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(guard.GetCore().SubscribeAvailableDeviceStatus(USER, CallerInfo { .name = FOREGROUND_TEST_BUNDLE }, cb),
        ResultCode::SUCCESS);
    DrainPendingTasks();

    EXPECT_TRUE(IsManageMode());
}

// HAP subscriber, then its window becomes invisible -> AUTH.
HWTEST_F(SubscribeModeModuleTest, HapBackground_Auth_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr UserId USER = 100;

    auto cb = sptr<FakeSubscriberCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(guard.GetCore().SubscribeAvailableDeviceStatus(USER, CallerInfo { .name = FOREGROUND_TEST_BUNDLE }, cb),
        ResultCode::SUCCESS);
    DrainPendingTasks();
    EXPECT_TRUE(IsManageMode());

    guard.GetAppForegroundStateAdapter().TestSimulateStateChanged(FOREGROUND_TEST_BUNDLE, false);
    DrainPendingTasks();
    EXPECT_FALSE(IsManageMode());
}

// Two HAP subscribers: one background + one foreground -> MANAGE; losing the last foreground -> AUTH.
HWTEST_F(SubscribeModeModuleTest, MultiHapOneForeground_Manage_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr UserId USER = 100;
    guard.GetAppForegroundStateAdapter().TestSetForegroundBundles({ "b.app" }); // only B is foreground

    auto cbA = sptr<FakeSubscriberCallback>::MakeSptr();
    auto cbB = sptr<FakeSubscriberCallback>::MakeSptr();
    ASSERT_NE(cbA, nullptr);
    ASSERT_NE(cbB, nullptr);
    EXPECT_EQ(guard.GetCore().SubscribeAvailableDeviceStatus(USER, CallerInfo { .name = "a.app" }, cbA),
        ResultCode::SUCCESS);
    EXPECT_EQ(guard.GetCore().SubscribeAvailableDeviceStatus(USER, CallerInfo { .name = "b.app" }, cbB),
        ResultCode::SUCCESS);
    DrainPendingTasks();
    EXPECT_TRUE(IsManageMode()); // B is foreground

    guard.GetAppForegroundStateAdapter().TestSimulateStateChanged("b.app", false);
    DrainPendingTasks();
    EXPECT_FALSE(IsManageMode()); // all subscribers background
}

// A Native (non-HAP) subscriber is a background process and must not pin MANAGE; with nothing
// in the foreground the mode stays AUTH.
HWTEST_F(SubscribeModeModuleTest, NativeSubscriber_NoManage_001, TestSize.Level0)
{
    ModuleTestGuard guard;
    constexpr UserId USER = 100;
    guard.GetAppForegroundStateAdapter().TestSetForegroundBundles({}); // nothing foreground

    auto cb = sptr<FakeSubscriberCallback>::MakeSptr();
    ASSERT_NE(cb, nullptr);
    EXPECT_EQ(guard.GetCore().SubscribeAvailableDeviceStatus(USER,
                  CallerInfo { .name = "native.proc", .type = CallerTokenType::Native }, cb),
        ResultCode::SUCCESS);
    DrainPendingTasks();

    EXPECT_FALSE(IsManageMode());
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
