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
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iam_logger.h"

#include "adapter_manager.h"
#include "sa_manager_adapter.h"
#include "sa_manager_adapter_impl.h"

#include "mock_sa_manager_adapter.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace testing;
using namespace testing::ext;

namespace {
}

class SaManagerAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void SaManagerAdapterTest::SetUpTestCase()
{
}

void SaManagerAdapterTest::TearDownTestCase()
{
}

void SaManagerAdapterTest::SetUp()
{
    AdapterManager::GetInstance().SetSaManagerAdapter(nullptr);
}

void SaManagerAdapterTest::TearDown()
{
    AdapterManager::GetInstance().SetSaManagerAdapter(nullptr);
}

HWTEST_F(SaManagerAdapterTest, CreateDefaultAdapter, TestSize.Level0)
{
    auto adapter = std::make_shared<SaManagerAdapterImpl>();
    ASSERT_NE(adapter, nullptr);
}

HWTEST_F(SaManagerAdapterTest, RegisterToSingleton, TestSize.Level0)
{
    auto adapter = std::make_shared<SaManagerAdapterImpl>();
    AdapterManager::GetInstance().SetSaManagerAdapter(adapter);

    ISaManagerAdapter &retrieved = GetSaManagerAdapter();
    EXPECT_EQ(&retrieved, adapter.get());
}

HWTEST_F(SaManagerAdapterTest, SubscribeSystemAbilityWithNegativeId, TestSize.Level0)
{
    auto adapter = std::make_shared<SaManagerAdapterImpl>();

    sptr<SystemAbilityStatusChangeStub> listener = nullptr;
    adapter->SubscribeSystemAbility(-1, listener);
    // Should not crash
}

HWTEST_F(SaManagerAdapterTest, UnSubscribeSystemAbilityWithNullListener, TestSize.Level0)
{
    auto adapter = std::make_shared<SaManagerAdapterImpl>();

    sptr<SystemAbilityStatusChangeStub> listener = nullptr;
    adapter->UnSubscribeSystemAbility(100, listener);
    // Should not crash
}

HWTEST_F(SaManagerAdapterTest, MockAdapterInjection, TestSize.Level0)
{
    auto mockAdapter = std::make_shared<MockSAManagerAdapter>();
    AdapterManager::GetInstance().SetSaManagerAdapter(mockAdapter);

    ISaManagerAdapter &adapter = GetSaManagerAdapter();
    EXPECT_EQ(&adapter, mockAdapter.get());
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
