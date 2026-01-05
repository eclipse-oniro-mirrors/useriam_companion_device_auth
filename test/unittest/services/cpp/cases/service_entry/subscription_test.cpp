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

#include <gtest/gtest.h>

#include "subscription.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SubscriptionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void SubscriptionTest::SetUpTestCase()
{
}

void SubscriptionTest::TearDownTestCase()
{
}

void SubscriptionTest::SetUp()
{
}

void SubscriptionTest::TearDown()
{
}

HWTEST_F(SubscriptionTest, Constructor_001, TestSize.Level0)
{
    bool cleanupCalled = false;
    auto cleanup = [&cleanupCalled]() { cleanupCalled = true; };

    {
        Subscription subscription(std::move(cleanup));
    }

    EXPECT_TRUE(cleanupCalled);
}

HWTEST_F(SubscriptionTest, Cancel_001, TestSize.Level0)
{
    bool cleanupCalled = false;
    auto cleanup = [&cleanupCalled]() { cleanupCalled = true; };

    {
        Subscription subscription(std::move(cleanup));
        subscription.Cancel();
    }

    EXPECT_TRUE(cleanupCalled);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
