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

#include "mock_guard.h"

#include "companion_request_resync_request.h"
#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_200 = 200;

class CompanionRequestResyncRequestTest : public Test {
protected:
    DeviceKey MakeHostKey(const std::string &deviceId, UserId deviceUserId)
    {
        return DeviceKey { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
            .deviceId = deviceId,
            .deviceUserId = deviceUserId };
    }
};

HWTEST_F(CompanionRequestResyncRequestTest, ShouldCancelOnNewRequest_SamePhysicalDevice, TestSize.Level0)
{
    MockGuard guard;
    CompanionRequestResyncRequest mine(MakeHostKey("host_A", INT32_100), "active_user_changed");
    CompanionRequestResyncRequest next(MakeHostKey("host_A", INT32_200), "device_name_changed");

    EXPECT_TRUE(mine.ShouldCancelOnNewRequest(next, 0));
}

HWTEST_F(CompanionRequestResyncRequestTest, ShouldCancelOnNewRequest_DifferentPhysicalDevice, TestSize.Level0)
{
    MockGuard guard;
    CompanionRequestResyncRequest mine(MakeHostKey("host_A", INT32_100), "active_user_changed");
    CompanionRequestResyncRequest next(MakeHostKey("host_B", INT32_100), "device_name_changed");

    EXPECT_FALSE(mine.ShouldCancelOnNewRequest(next, 0));
}

HWTEST_F(CompanionRequestResyncRequestTest, GetMaxConcurrency_AllowsMultipleHosts, TestSize.Level0)
{
    MockGuard guard;
    CompanionRequestResyncRequest request(MakeHostKey("host_A", INT32_100), "active_user_changed");

    EXPECT_GT(request.GetMaxConcurrency(), 1u);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
