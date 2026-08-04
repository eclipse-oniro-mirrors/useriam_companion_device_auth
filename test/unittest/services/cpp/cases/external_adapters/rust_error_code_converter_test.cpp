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

#include <gtest/gtest.h>

#include "security_command_adapter_impl.h"

using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

HWTEST(RustErrorCodeConverterTest, AllKnownMappings, TestSize.Level0)
{
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::SUCCESS)), ResultCode::SUCCESS);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::FAIL)), ResultCode::FAIL);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::GENERAL_ERROR)), ResultCode::GENERAL_ERROR);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::TIMEOUT)), ResultCode::TIMEOUT);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::BAD_PARAM)), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::NOT_FOUND)), ResultCode::NOT_ENROLLED);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::ID_EXISTS)), ResultCode::INVALID_PARAMETERS);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::EXCEED_LIMIT)), ResultCode::EXCEED_LIMIT);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::TOKEN_NOT_FOUND)), ResultCode::TOKEN_NOT_FOUND);
    EXPECT_EQ(ConvertRustErrorCode(static_cast<int32_t>(RustErrorCode::TOKEN_VERIFY_FAILED)),
        ResultCode::TOKEN_VERIFY_FAILED);
}

HWTEST(RustErrorCodeConverterTest, UnknownCodeFallsBackToGeneralError, TestSize.Level0)
{
    EXPECT_EQ(ConvertRustErrorCode(99999), ResultCode::GENERAL_ERROR);
    EXPECT_EQ(ConvertRustErrorCode(-1), ResultCode::GENERAL_ERROR);
    EXPECT_EQ(ConvertRustErrorCode(3), ResultCode::GENERAL_ERROR); // gap between GENERAL_ERROR(2) and TIMEOUT(4)
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
