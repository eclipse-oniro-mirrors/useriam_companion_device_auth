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

#include "callback_death_recipient.h"
#include "mock_remote_object.h"

#include "iam_logger.h"
#define LOG_TAG "COMPANION_DEVICE_AUTH"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CallbackDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CallbackDeathRecipientTest::SetUpTestCase()
{
}

void CallbackDeathRecipientTest::TearDownTestCase()
{
}

void CallbackDeathRecipientTest::SetUp()
{
}

void CallbackDeathRecipientTest::TearDown()
{
}

HWTEST_F(CallbackDeathRecipientTest, Create_001, TestSize.Level0)
{
    sptr<CallbackDeathRecipient> recipient;

    {
        sptr<MockRemoteObject> remoteObj = sptr<MockRemoteObject>::MakeSptr();
        ASSERT_NE(remoteObj, nullptr);

        bool callbackCalled = false;
        auto callback = [&callbackCalled]() { callbackCalled = true; };

        EXPECT_CALL(*remoteObj, AddDeathRecipient(_)).WillOnce(Return(true));

        recipient = CallbackDeathRecipient::Create(remoteObj, std::move(callback));
        EXPECT_NE(recipient, nullptr);
    }

    recipient = nullptr;
}

HWTEST_F(CallbackDeathRecipientTest, Create_002, TestSize.Level0)
{
    sptr<IRemoteObject> remoteObj = nullptr;
    bool callbackCalled = false;
    auto callback = [&callbackCalled]() { callbackCalled = true; };

    auto recipient = CallbackDeathRecipient::Create(remoteObj, std::move(callback));
    EXPECT_EQ(recipient, nullptr);
}

HWTEST_F(CallbackDeathRecipientTest, Create_003, TestSize.Level0)
{
    sptr<CallbackDeathRecipient> recipient;

    {
        sptr<MockRemoteObject> remoteObj = sptr<MockRemoteObject>::MakeSptr();
        ASSERT_NE(remoteObj, nullptr);

        CallbackDeathRecipient::DeathCallback callback = nullptr;

        recipient = CallbackDeathRecipient::Create(remoteObj, std::move(callback));
        EXPECT_EQ(recipient, nullptr);
    }
}

HWTEST_F(CallbackDeathRecipientTest, Create_004, TestSize.Level0)
{
    sptr<CallbackDeathRecipient> recipient;

    {
        sptr<MockRemoteObject> remoteObj = sptr<MockRemoteObject>::MakeSptr();
        ASSERT_NE(remoteObj, nullptr);

        bool callbackCalled = false;
        auto callback = [&callbackCalled]() { callbackCalled = true; };

        EXPECT_CALL(*remoteObj, AddDeathRecipient(_)).WillOnce(Return(false));

        recipient = CallbackDeathRecipient::Create(remoteObj, std::move(callback));
        EXPECT_EQ(recipient, nullptr);
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
