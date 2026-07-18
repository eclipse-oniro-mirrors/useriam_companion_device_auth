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

#include "subscription_util.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

CompanionStatus MakeStatus(uint64_t lastCheckTime)
{
    CompanionStatus status;
    status.companionDeviceStatus.lastSyncTimeMs = lastCheckTime;
    return status;
}

} // namespace

class SubscriptionUtilTest : public Test {};

// isConfirmed is true at the boundary: the device synced exactly when manage mode began.
HWTEST_F(SubscriptionUtilTest, ConvertToIpcTemplateStatus_ConfirmedAtBoundary, TestSize.Level0)
{
    auto status = MakeStatus(100);
    std::optional<int64_t> manageSubscribeTime = 100;
    auto ipcStatus = ConvertToIpcTemplateStatus(status, manageSubscribeTime);
    EXPECT_TRUE(ipcStatus.isConfirmed);
}

// isConfirmed is true when the device synced after manage mode began.
HWTEST_F(SubscriptionUtilTest, ConvertToIpcTemplateStatus_ConfirmedAfterSubscribe, TestSize.Level0)
{
    auto status = MakeStatus(200);
    std::optional<int64_t> manageSubscribeTime = 100;
    auto ipcStatus = ConvertToIpcTemplateStatus(status, manageSubscribeTime);
    EXPECT_TRUE(ipcStatus.isConfirmed);
}

// isConfirmed is false when the last sync predates manage mode (stale status).
HWTEST_F(SubscriptionUtilTest, ConvertToIpcTemplateStatus_NotConfirmedBeforeSubscribe, TestSize.Level0)
{
    auto status = MakeStatus(50);
    std::optional<int64_t> manageSubscribeTime = 100;
    auto ipcStatus = ConvertToIpcTemplateStatus(status, manageSubscribeTime);
    EXPECT_FALSE(ipcStatus.isConfirmed);
}

// isConfirmed is false outside manage mode, regardless of sync time.
HWTEST_F(SubscriptionUtilTest, ConvertToIpcTemplateStatus_NotConfirmedWithoutManageSubscribe, TestSize.Level0)
{
    auto status = MakeStatus(200);
    std::optional<int64_t> manageSubscribeTime = std::nullopt;
    auto ipcStatus = ConvertToIpcTemplateStatus(status, manageSubscribeTime);
    EXPECT_FALSE(ipcStatus.isConfirmed);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
