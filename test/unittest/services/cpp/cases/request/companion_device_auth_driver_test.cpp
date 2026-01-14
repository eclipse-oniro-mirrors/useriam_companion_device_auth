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

#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "companion_auth_interface_adapter.h"
#include "companion_device_auth_driver.h"
#include "fwk_common.h"
#include "singleton_manager.h"
#include "user_id_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
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
    int32_t activeUserId_ { 100 };
    ActiveUserIdCallback activeUserIdCallback_ {};
};
} // namespace

class CompanionDeviceAuthDriverTest : public Test {
public:
    void SetUp() override
    {
        SingletonManager::GetInstance().Reset();
        auto activeUserIdMgr = std::make_shared<FakeUserIdManager>();
        SingletonManager::GetInstance().SetActiveUserIdManager(activeUserIdMgr);
        adapter_ = std::make_shared<CompanionAuthInterfaceAdapter>();
    }

    void TearDown() override
    {
        adapter_.reset();
        SingletonManager::GetInstance().Reset();
    }

protected:
    std::shared_ptr<CompanionAuthInterfaceAdapter> adapter_;
};

HWTEST_F(CompanionDeviceAuthDriverTest, Constructor_001, TestSize.Level0)
{
    auto driver = std::make_unique<CompanionDeviceAuthDriver>(adapter_);
    EXPECT_NE(nullptr, driver);
}

HWTEST_F(CompanionDeviceAuthDriverTest, GetExecutorList_001, TestSize.Level0)
{
    auto driver = std::make_unique<CompanionDeviceAuthDriver>(adapter_);
    ASSERT_NE(nullptr, driver);

    std::vector<std::shared_ptr<FwkIAuthExecutorHdi>> executorList;
    driver->GetExecutorList(executorList);

    EXPECT_EQ(1u, executorList.size());
    EXPECT_NE(nullptr, executorList[0]);
}

HWTEST_F(CompanionDeviceAuthDriverTest, OnHdiDisconnect_001, TestSize.Level0)
{
    auto driver = std::make_unique<CompanionDeviceAuthDriver>(adapter_);
    ASSERT_NE(nullptr, driver);

    driver->OnHdiDisconnect();
    EXPECT_TRUE(true);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
