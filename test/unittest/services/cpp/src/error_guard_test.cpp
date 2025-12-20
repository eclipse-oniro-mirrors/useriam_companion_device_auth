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

#include <gtest/gtest.h>

#include "common_defines.h"
#include "error_guard.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

class AsyncErrorGuardTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AsyncErrorGuardTest::SetUpTestCase()
{
}

void AsyncErrorGuardTest::TearDownTestCase()
{
}

void AsyncErrorGuardTest::SetUp()
{
}

void AsyncErrorGuardTest::TearDown()
{
}

HWTEST_F(AsyncErrorGuardTest, DefaultErrorCode_001, TestSize.Level0)
{
    ResultCode capturedCode = ResultCode::SUCCESS;
    {
        ErrorGuard guard([&capturedCode](ResultCode code) { capturedCode = code; });
    }
    EXPECT_EQ(capturedCode, ResultCode::GENERAL_ERROR);
}

HWTEST_F(AsyncErrorGuardTest, UpdateErrorCode_001, TestSize.Level0)
{
    ResultCode capturedCode = ResultCode::SUCCESS;
    {
        ErrorGuard guard([&capturedCode](ResultCode code) { capturedCode = code; });
        guard.UpdateErrorCode(ResultCode::INVALID_PARAMETERS);
    }
    EXPECT_EQ(capturedCode, ResultCode::INVALID_PARAMETERS);
}

HWTEST_F(AsyncErrorGuardTest, Cancel_001, TestSize.Level0)
{
    ResultCode capturedCode = ResultCode::SUCCESS;
    {
        ErrorGuard guard([&capturedCode](ResultCode code) { capturedCode = code; });
        guard.Cancel();
    }
    EXPECT_EQ(capturedCode, ResultCode::SUCCESS);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
