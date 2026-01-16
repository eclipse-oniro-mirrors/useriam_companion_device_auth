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

#include "access_token_kit_adapter.h"
#include "access_token_kit_adapter_impl.h"
#include "adapter_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace testing;
using namespace testing::ext;

namespace {
}

class AccessTokenKitAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void AccessTokenKitAdapterTest::SetUpTestCase()
{
}

void AccessTokenKitAdapterTest::TearDownTestCase()
{
}

void AccessTokenKitAdapterTest::SetUp()
{
    // Reset adapter before each test
    AdapterManager::GetInstance().SetAccessTokenKitAdapter(nullptr);
}

void AccessTokenKitAdapterTest::TearDown()
{
    // Clean up after each test
    AdapterManager::GetInstance().SetAccessTokenKitAdapter(nullptr);
}

HWTEST_F(AccessTokenKitAdapterTest, CreateDefaultAdapter, TestSize.Level0)
{
    auto adapter = std::make_shared<AccessTokenKitAdapterImpl>();
    ASSERT_NE(adapter, nullptr);
}

HWTEST_F(AccessTokenKitAdapterTest, RegisterToSingleton, TestSize.Level0)
{
    auto adapter = std::make_shared<AccessTokenKitAdapterImpl>();
    AdapterManager::GetInstance().SetAccessTokenKitAdapter(adapter);

    IAccessTokenKitAdapter &retrieved = GetAccessTokenKitAdapter();
    EXPECT_EQ(&retrieved, adapter.get());
}

HWTEST_F(AccessTokenKitAdapterTest, MultipleAdapterInstances, TestSize.Level0)
{
    auto adapter1 = std::make_shared<AccessTokenKitAdapterImpl>();
    auto adapter2 = std::make_shared<AccessTokenKitAdapterImpl>();

    EXPECT_NE(adapter1, nullptr);
    EXPECT_NE(adapter2, nullptr);
    EXPECT_NE(adapter1, adapter2);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
