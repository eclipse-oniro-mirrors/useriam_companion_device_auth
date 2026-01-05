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
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "iam_logger.h"

#include "adapter_manager.h"
#include "user_auth_adapter.h"
#include "user_auth_adapter_impl.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace testing;
using namespace testing::ext;

class UserAuthAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void UserAuthAdapterTest::SetUpTestCase()
{
}

void UserAuthAdapterTest::TearDownTestCase()
{
}

void UserAuthAdapterTest::SetUp()
{
    AdapterManager::GetInstance().SetUserAuthAdapter(nullptr);
}

void UserAuthAdapterTest::TearDown()
{
    AdapterManager::GetInstance().SetUserAuthAdapter(nullptr);
}

HWTEST_F(UserAuthAdapterTest, CreateDefaultAdapter, TestSize.Level0)
{
    auto adapter = std::make_shared<UserAuthAdapterImpl>();
    ASSERT_NE(adapter, nullptr);
}

HWTEST_F(UserAuthAdapterTest, RegisterToSingleton, TestSize.Level0)
{
    auto adapter = std::make_shared<UserAuthAdapterImpl>();
    AdapterManager::GetInstance().SetUserAuthAdapter(adapter);

    IUserAuthAdapter &retrieved = GetUserAuthAdapter();
    EXPECT_EQ(&retrieved, adapter.get());
}

HWTEST_F(UserAuthAdapterTest, BeginDelegateAuthWithNullCallback, TestSize.Level0)
{
    auto adapter = std::make_shared<UserAuthAdapterImpl>();

    DelegateAuthParam param;
    param.userId = 100;
    param.challenge = std::vector<uint8_t> { 't', 'e', 's', 't' };
    param.authTrustLevel = 10000;

    uint64_t result = adapter->BeginDelegateAuth(param, nullptr);
    EXPECT_EQ(result, 0);
}

HWTEST_F(UserAuthAdapterTest, BeginDelegateAuthWithEmptyChallenge, TestSize.Level0)
{
    auto adapter = std::make_shared<UserAuthAdapterImpl>();

    DelegateAuthParam param;
    param.userId = 100;
    param.challenge = {};
    param.authTrustLevel = 10000;

    uint64_t result = adapter->BeginDelegateAuth(param, nullptr);
    EXPECT_EQ(result, 0);
}

HWTEST_F(UserAuthAdapterTest, CancelAuthenticationWithInvalidContext, TestSize.Level0)
{
    auto adapter = std::make_shared<UserAuthAdapterImpl>();

    int32_t result = adapter->CancelAuthentication(0);
    EXPECT_NE(result, 0);
}

HWTEST_F(UserAuthAdapterTest, MultipleAdapterInstances, TestSize.Level0)
{
    auto adapter1 = std::make_shared<UserAuthAdapterImpl>();
    auto adapter2 = std::make_shared<UserAuthAdapterImpl>();

    EXPECT_NE(adapter1, nullptr);
    EXPECT_NE(adapter2, nullptr);
    EXPECT_NE(adapter1, adapter2);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
