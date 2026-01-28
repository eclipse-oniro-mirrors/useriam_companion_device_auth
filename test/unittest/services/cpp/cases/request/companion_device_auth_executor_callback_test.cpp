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

#include "companion_device_auth_executor_callback.h"
#include "mock_guard.h"
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

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_001, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::GENERAL_ERROR);

    EXPECT_EQ(result, FwkResultCode::GENERAL_ERROR);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_002, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::CANCELED);

    EXPECT_EQ(result, FwkResultCode::CANCELED);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_003, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::TIMEOUT);

    EXPECT_EQ(result, FwkResultCode::TIMEOUT);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_004, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::TYPE_NOT_SUPPORT);

    EXPECT_EQ(result, FwkResultCode::TYPE_NOT_SUPPORT);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_005, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::TRUST_LEVEL_NOT_SUPPORT);

    EXPECT_EQ(result, FwkResultCode::TRUST_LEVEL_NOT_SUPPORT);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_006, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::BUSY);

    EXPECT_EQ(result, FwkResultCode::BUSY);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_007, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::INVALID_PARAMETERS);

    EXPECT_EQ(result, FwkResultCode::INVALID_PARAMETERS);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_008, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::LOCKED);

    EXPECT_EQ(result, FwkResultCode::LOCKED);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_009, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::NOT_ENROLLED);

    EXPECT_EQ(result, FwkResultCode::NOT_ENROLLED);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_010, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::CANCELED_FROM_WIDGET);

    EXPECT_EQ(result, FwkResultCode::CANCELED_FROM_WIDGET);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_011, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::HARDWARE_NOT_SUPPORTED);

    EXPECT_EQ(result, FwkResultCode::HARDWARE_NOT_SUPPORTED);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_012, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::PIN_EXPIRED);

    EXPECT_EQ(result, FwkResultCode::PIN_EXPIRED);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_013, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::COMPLEXITY_CHECK_FAILED);

    EXPECT_EQ(result, FwkResultCode::COMPLEXITY_CHECK_FAILED);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_014, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::AUTH_TOKEN_CHECK_FAILED);

    EXPECT_EQ(result, FwkResultCode::AUTH_TOKEN_CHECK_FAILED);
}

HWTEST_F(CompanionDeviceAuthExecutorCallbackTest, ConvertResultCode_015, TestSize.Level0)
{
    MockGuard guard;
    auto mockCallback = CreateMockCallback();
    auto callback = std::make_shared<CompanionDeviceAuthExecutorCallback>(mockCallback);
    ASSERT_NE(nullptr, callback);

    FwkResultCode result = callback->ConvertResultCode(ResultCode::AUTH_TOKEN_EXPIRED);

    EXPECT_EQ(result, FwkResultCode::AUTH_TOKEN_EXPIRED);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
