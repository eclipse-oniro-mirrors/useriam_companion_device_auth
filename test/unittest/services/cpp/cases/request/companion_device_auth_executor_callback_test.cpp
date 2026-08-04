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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mock_guard.h"

#include "companion_device_auth_executor_callback.h"
#include "service_common.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class MockFwkExecuteCallback : public FwkIExecuteCallback {
public:
    MOCK_METHOD(void, OnResult, (FwkResultCode result, const std::vector<uint8_t> &extraInfo), (override));
    MOCK_METHOD(void, OnResult, (FwkResultCode result), (override));
    MOCK_METHOD(void, OnAcquireInfo, (int32_t acquire, const std::vector<uint8_t> &extraInfo), (override));
    MOCK_METHOD(void, OnMessage, (int destRole, const std::vector<uint8_t> &msg), (override));
};

class CompanionDeviceAuthExecutorCallbackTest : public Test {
public:
    std::shared_ptr<MockFwkExecuteCallback> CreateMockCallback()
    {
        return std::make_shared<NiceMock<MockFwkExecuteCallback>>();
    }
};

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, Constructor_001, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    EXPECT_NE(nullptr, callback);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, OperatorCall_001, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    EXPECT_CALL(*mockCallback, OnResult(FwkResultCode::SUCCESS, _)).Times(1);

    std::vector<uint8_t> extraInfo = { 1, 2, 3 };
    (*callback)(ResultCode::SUCCESS, extraInfo);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, OperatorCall_002, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    EXPECT_CALL(*mockCallback, OnResult(FwkResultCode::FAIL, _)).Times(1);

    std::vector<uint8_t> extraInfo;
    (*callback)(ResultCode::COMMUNICATION_ERROR, extraInfo);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, OperatorCall_003, TestSize.Level0)
{
    MockGuard guard;
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(nullptr);
    ASSERT_NE(nullptr, callback);
    callback->frameworkCallback_ = nullptr;

    std::vector<uint8_t> extraInfo;
    (*callback)(ResultCode::FAIL, extraInfo);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
