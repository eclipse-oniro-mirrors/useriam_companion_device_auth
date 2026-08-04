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

#include <memory>
#include <optional>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "fake_companion_device_auth.h"

#include "companion_device_auth_client.h"
#include "companion_device_auth_client_impl.h"
#include "status_monitor.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

namespace {
// Minimal payload wrapped by ContinuousAuthStatusCallbackWrapper<C>. operator== on the wrapper compares the payload,
// which is how CallbackHolder::RemoveCallback tells callbacks apart. Distinct values model distinct JS/ANI callbacks.
using TestCallback = int;

constexpr size_t INDEX_1 = 1;
constexpr size_t INDEX_2 = 2;
constexpr int32_t INT32_0 = 0;
constexpr int32_t TEST_USER_ID = 100;
constexpr TestCallback CALLBACK_1 = 1;
constexpr TestCallback CALLBACK_2 = 2;
constexpr uint64_t TEMPLATE_ID_1 = 1001;
constexpr uint64_t TEMPLATE_ID_2 = 1002;
} // namespace

// ContinuousAuthStatusCallbackWrapper<C>::OnContinuousAuthStatusChange is only defined (in the napi/ani sources) for
// the real C types. Constructing wrapper instances emits their vtable, so provide a definition for the test payload.
namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
template <>
void ContinuousAuthStatusCallbackWrapper<TestCallback>::OnContinuousAuthStatusChange(const bool isAuthPassed,
    const std::optional<int32_t> authTrustLevel)
{
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

class StatusMonitorTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

protected:
    FakeCompanionDeviceAuth *fakeProxy_ = nullptr;
};

void StatusMonitorTest::SetUp()
{
    fakeProxy_ = new (std::nothrow) FakeCompanionDeviceAuth();
    ASSERT_NE(fakeProxy_, nullptr);
    // StatusMonitor talks to CompanionDeviceAuthClient::GetInstance(); inject the fake so subscribe/unsubscribe
    // succeed and the client registers the holders (lets the unsubscribe path find them on removal).
    ON_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_2>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, UnsubscribeContinuousAuthStatusChange(_, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_1>(INT32_0), Return(INT32_0)));
    static_cast<CompanionDeviceAuthClientImpl &>(CompanionDeviceAuthClient::GetInstance())
        .SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
}

void StatusMonitorTest::TearDown()
{
    Mock::AllowLeak(fakeProxy_);
    fakeProxy_ = nullptr;
}

/**
 * @brief Regression: off(callback) must not abort on the first templateId bucket that does not hold it.
 *
 * Map {t1:[cb1], t2:[cb2]}, off(cb2): t1 is iterated first and does not contain cb2, which is normal while
 * searching. The old code did `return ret` on that not-found bucket, so cb2 stayed registered and the call
 * returned GENERAL_ERROR. The fix keeps scanning and only fails if no bucket holds the callback.
 */
HWTEST_F(StatusMonitorTest, OffContinuousAuthChange_RemovesCallbackFromLaterBucket, TestSize.Level0)
{
    StatusMonitor<TestCallback, TestCallback, TestCallback> monitor(TEST_USER_ID);
    auto cb1 = std::make_shared<ContinuousAuthStatusCallbackWrapper<TestCallback>>(CALLBACK_1);
    auto cb2 = std::make_shared<ContinuousAuthStatusCallbackWrapper<TestCallback>>(CALLBACK_2);
    ASSERT_EQ(monitor.OnContinuousAuthChange(TEMPLATE_ID_1, cb1), SUCCESS);
    ASSERT_EQ(monitor.OnContinuousAuthChange(TEMPLATE_ID_2, cb2), SUCCESS);
    ASSERT_EQ(monitor.continuousAuthStatusCallbackMap_.size(), 2u);

    int32_t ret = monitor.OffContinuousAuthChange(cb2);

    EXPECT_EQ(ret, SUCCESS);
    // cb2 removed and its now-empty bucket erased; cb1 untouched in its own bucket.
    EXPECT_EQ(monitor.continuousAuthStatusCallbackMap_.count(std::optional<uint64_t>(TEMPLATE_ID_2)), 0u);
    EXPECT_EQ(monitor.continuousAuthStatusCallbackMap_.count(std::optional<uint64_t>(TEMPLATE_ID_1)), 1u);
}

/**
 * @brief off(callback) returns GENERAL_ERROR when the callback was never registered under any templateId.
 */
HWTEST_F(StatusMonitorTest, OffContinuousAuthChange_NotRegisteredReturnsError, TestSize.Level0)
{
    StatusMonitor<TestCallback, TestCallback, TestCallback> monitor(TEST_USER_ID);
    auto cb1 = std::make_shared<ContinuousAuthStatusCallbackWrapper<TestCallback>>(CALLBACK_1);
    auto unregistered = std::make_shared<ContinuousAuthStatusCallbackWrapper<TestCallback>>(CALLBACK_2);
    ASSERT_EQ(monitor.OnContinuousAuthChange(TEMPLATE_ID_1, cb1), SUCCESS);

    int32_t ret = monitor.OffContinuousAuthChange(unregistered);

    EXPECT_EQ(ret, GENERAL_ERROR);
    // The registered callback is untouched.
    EXPECT_EQ(monitor.continuousAuthStatusCallbackMap_.count(std::optional<uint64_t>(TEMPLATE_ID_1)), 1u);
}

/**
 * @brief off(callback) keeps the bucket when other callbacks remain under the same templateId (no unsubscribe).
 */
HWTEST_F(StatusMonitorTest, OffContinuousAuthChange_KeepsBucketWhenOthersRemain, TestSize.Level0)
{
    StatusMonitor<TestCallback, TestCallback, TestCallback> monitor(TEST_USER_ID);
    auto cb1 = std::make_shared<ContinuousAuthStatusCallbackWrapper<TestCallback>>(CALLBACK_1);
    auto cb2 = std::make_shared<ContinuousAuthStatusCallbackWrapper<TestCallback>>(CALLBACK_2);
    ASSERT_EQ(monitor.OnContinuousAuthChange(TEMPLATE_ID_1, cb1), SUCCESS);
    ASSERT_EQ(monitor.OnContinuousAuthChange(TEMPLATE_ID_1, cb2), SUCCESS);

    int32_t ret = monitor.OffContinuousAuthChange(cb1);

    EXPECT_EQ(ret, SUCCESS);
    // Bucket retained with cb2 still registered.
    EXPECT_EQ(monitor.continuousAuthStatusCallbackMap_.count(std::optional<uint64_t>(TEMPLATE_ID_1)), 1u);
}
