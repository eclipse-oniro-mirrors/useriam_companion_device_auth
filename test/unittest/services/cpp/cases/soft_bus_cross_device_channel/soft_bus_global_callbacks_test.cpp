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

#include "relative_timer.h"
#include "singleton_manager.h"
#include "soft_bus_connection_manager.h"
#include "soft_bus_global_callbacks.h"
#include "task_runner_manager.h"

#include "adapter_manager.h"
#include "mock_misc_manager.h"
#include "mock_time_keeper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr uint64_t UINT64_1 = 1;

class SoftBusGlobalCallbacksTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();

        auto miscMgr = std::shared_ptr<IMiscManager>(&mockMiscManager_, [](IMiscManager *) {});
        SingletonManager::GetInstance().SetMiscManager(miscMgr);

        auto timeKeeper = std::make_shared<MockTimeKeeper>();
        AdapterManager::GetInstance().SetTimeKeeper(timeKeeper);

        ON_CALL(mockMiscManager_, GetNextGlobalId()).WillByDefault([this]() { return nextGlobalId_++; });
    }

    void TearDown() override
    {
        TaskRunnerManager::GetInstance().ExecuteAll();
        RelativeTimer::GetInstance().ExecuteAll();
        SingletonManager::GetInstance().Reset();
        AdapterManager::GetInstance().Reset();
    }

protected:
    uint64_t nextGlobalId_ = UINT64_1;
    NiceMock<MockMiscManager> mockMiscManager_;
};

HWTEST_F(SoftBusGlobalCallbacksTest, SetGlobalSoftBusConnectionManager_001, TestSize.Level0)
{
    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    SetGlobalSoftBusConnectionManager(manager);
}

HWTEST_F(SoftBusGlobalCallbacksTest, SetGlobalSoftBusConnectionManager_002, TestSize.Level0)
{
    std::weak_ptr<SoftBusConnectionManager> weakManager;
    EXPECT_NO_THROW(SetGlobalSoftBusConnectionManager(weakManager));
}

HWTEST_F(SoftBusGlobalCallbacksTest, ClearGlobalSoftBusConnectionManager_001, TestSize.Level0)
{
    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    SetGlobalSoftBusConnectionManager(manager);
    ClearGlobalSoftBusConnectionManager(manager.get());
}

HWTEST_F(SoftBusGlobalCallbacksTest, ClearGlobalSoftBusConnectionManager_002, TestSize.Level0)
{
    EXPECT_NO_THROW(ClearGlobalSoftBusConnectionManager(nullptr));
}

HWTEST_F(SoftBusGlobalCallbacksTest, ClearGlobalSoftBusConnectionManager_003, TestSize.Level0)
{
    auto manager1 = SoftBusConnectionManager::Create();
    auto manager2 = SoftBusConnectionManager::Create();
    ASSERT_NE(manager1, nullptr);
    ASSERT_NE(manager2, nullptr);

    SetGlobalSoftBusConnectionManager(manager1);
    ClearGlobalSoftBusConnectionManager(manager2.get());
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBind_001, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[] = "ohos.companiondeviceauth";
    char networkId[] = "test-network-id";
    info.pkgName = pkgName;
    info.networkId = networkId;

    SoftBusOnBind(100, info);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBind_002, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[] = "ohos.companiondeviceauth";
    char networkId[] = "test-network-id";
    info.pkgName = pkgName;
    info.networkId = networkId;

    EXPECT_NO_THROW(SoftBusOnBind(-1, info));
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBind_003, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[] = "ohos.companiondeviceauth";
    info.pkgName = pkgName;
    info.networkId = nullptr;

    EXPECT_NO_THROW(SoftBusOnBind(100, info));
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBind_004, TestSize.Level0)
{
    PeerSocketInfo info;
    char networkId[] = "test-network-id";
    info.pkgName = nullptr;
    info.networkId = networkId;

    EXPECT_NO_THROW(SoftBusOnBind(100, info));
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBind_005, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[] = "wrong.package";
    char networkId[] = "test-network-id";
    info.pkgName = pkgName;
    info.networkId = networkId;

    EXPECT_NO_THROW(SoftBusOnBind(100, info));
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBind_006, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[] = "ohos.companiondeviceauth";
    char networkId[65];
    std::fill(std::begin(networkId), std::end(networkId), 'A');
    info.pkgName = pkgName;
    info.networkId = networkId;

    EXPECT_NO_THROW(SoftBusOnBind(100, info));
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnShutdown_001, TestSize.Level0)
{
    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    SetGlobalSoftBusConnectionManager(manager);

    SoftBusOnShutdown(100, SHUTDOWN_REASON_LOCAL);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnShutdown_002, TestSize.Level0)
{
    EXPECT_NO_THROW(SoftBusOnShutdown(-1, SHUTDOWN_REASON_LOCAL));
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnShutdown_003, TestSize.Level0)
{
    SoftBusOnShutdown(100, SHUTDOWN_REASON_LOCAL);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBytes_001, TestSize.Level0)
{
    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    SetGlobalSoftBusConnectionManager(manager);

    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    SoftBusOnBytes(100, data.data(), data.size());
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBytes_002, TestSize.Level0)
{
    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    EXPECT_NO_THROW(SoftBusOnBytes(-1, data.data(), data.size()));
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBytes_003, TestSize.Level0)
{
    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    SetGlobalSoftBusConnectionManager(manager);

    SoftBusOnBytes(100, nullptr, 10);
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBytes_004, TestSize.Level0)
{
    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    SetGlobalSoftBusConnectionManager(manager);

    std::vector<uint8_t> data(5000, 0xFF);
    SoftBusOnBytes(100, data.data(), data.size());
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnBytes_005, TestSize.Level0)
{
    std::vector<uint8_t> data = { 1, 2, 3, 4 };
    SoftBusOnBytes(100, data.data(), data.size());
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnError_001, TestSize.Level0)
{
    auto manager = SoftBusConnectionManager::Create();
    ASSERT_NE(manager, nullptr);

    SetGlobalSoftBusConnectionManager(manager);

    SoftBusOnError(100, 0);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnError_002, TestSize.Level0)
{
    EXPECT_NO_THROW(SoftBusOnError(-1, 0));
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnError_003, TestSize.Level0)
{
    SoftBusOnError(100, 0);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnNegotiate_001, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[] = "ohos.companiondeviceauth";
    info.pkgName = pkgName;

    bool result = SoftBusOnNegotiate(100, info);
    EXPECT_TRUE(result);
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnNegotiate_002, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[] = "ohos.companiondeviceauth";
    info.pkgName = pkgName;

    bool result = SoftBusOnNegotiate(-1, info);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnNegotiate_003, TestSize.Level0)
{
    PeerSocketInfo info;
    info.pkgName = nullptr;

    bool result = SoftBusOnNegotiate(100, info);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnNegotiate_004, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[] = "wrong.package";
    info.pkgName = pkgName;

    bool result = SoftBusOnNegotiate(100, info);
    EXPECT_FALSE(result);
}

HWTEST_F(SoftBusGlobalCallbacksTest, SoftBusOnNegotiate_005, TestSize.Level0)
{
    PeerSocketInfo info;
    char pkgName[65];
    std::fill(std::begin(pkgName), std::end(pkgName), 'A');
    info.pkgName = pkgName;

    bool result = SoftBusOnNegotiate(100, info);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
