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
#include <vector>

#include "common_defines.h"
#include "result_code_converter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// Ground-truth pairs kept independent of RESULT_CODE_MAPPINGS so a wrong table entry fails here.
struct ExpectedPair {
    ResultCode cda;
    UserAuth::ResultCode ua;
};

const std::vector<ExpectedPair> EXPECTED_PAIRS = {
    { ResultCode::SUCCESS, UserAuth::ResultCode::SUCCESS },
    { ResultCode::FAIL, UserAuth::ResultCode::FAIL },
    { ResultCode::GENERAL_ERROR, UserAuth::ResultCode::GENERAL_ERROR },
    { ResultCode::CANCELED, UserAuth::ResultCode::CANCELED },
    { ResultCode::TIMEOUT, UserAuth::ResultCode::TIMEOUT },
    { ResultCode::TYPE_NOT_SUPPORT, UserAuth::ResultCode::TYPE_NOT_SUPPORT },
    { ResultCode::TRUST_LEVEL_NOT_SUPPORT, UserAuth::ResultCode::TRUST_LEVEL_NOT_SUPPORT },
    { ResultCode::BUSY, UserAuth::ResultCode::BUSY },
    { ResultCode::INVALID_PARAMETERS, UserAuth::ResultCode::INVALID_PARAMETERS },
    { ResultCode::LOCKED, UserAuth::ResultCode::LOCKED },
    { ResultCode::NOT_ENROLLED, UserAuth::ResultCode::NOT_ENROLLED },
    { ResultCode::CANCELED_FROM_WIDGET, UserAuth::ResultCode::CANCELED_FROM_WIDGET },
    { ResultCode::HARDWARE_NOT_SUPPORTED, UserAuth::ResultCode::HARDWARE_NOT_SUPPORTED },
    { ResultCode::PIN_EXPIRED, UserAuth::ResultCode::PIN_EXPIRED },
    { ResultCode::COMPLEXITY_CHECK_FAILED, UserAuth::ResultCode::COMPLEXITY_CHECK_FAILED },
    { ResultCode::AUTH_TOKEN_CHECK_FAILED, UserAuth::ResultCode::AUTH_TOKEN_CHECK_FAILED },
    { ResultCode::AUTH_TOKEN_EXPIRED, UserAuth::ResultCode::AUTH_TOKEN_EXPIRED },
    { ResultCode::NO_VALID_CREDENTIAL, UserAuth::ResultCode::NO_VALID_CREDENTIAL },
};

class ResultCodeConverterTest : public Test {};

// ToUserAuthResultCode maps every known CDA code to its UserAuth equivalent.
HWTEST_F(ResultCodeConverterTest, ToUserAuth_KnownCodes, TestSize.Level0)
{
    for (const auto &p : EXPECTED_PAIRS) {
        EXPECT_EQ(ToUserAuthResultCode(p.cda), p.ua);
    }
}

// COMMUNICATION_ERROR is CDA-only and collapses to FAIL on the way to UserAuth.
HWTEST_F(ResultCodeConverterTest, ToUserAuth_CommunicationErrorCollapsesToFail, TestSize.Level0)
{
    EXPECT_EQ(ToUserAuthResultCode(ResultCode::COMMUNICATION_ERROR), UserAuth::ResultCode::FAIL);
}

// A CDA code with no UserAuth counterpart falls back to GENERAL_ERROR.
HWTEST_F(ResultCodeConverterTest, ToUserAuth_UnknownCodeReturnsGeneralError, TestSize.Level0)
{
    EXPECT_EQ(ToUserAuthResultCode(ResultCode::EXCEED_LIMIT), UserAuth::ResultCode::GENERAL_ERROR);
    EXPECT_EQ(ToUserAuthResultCode(ResultCode::CHECK_PERMISSION_FAILED), UserAuth::ResultCode::GENERAL_ERROR);
}

// FromUserAuthResultCode reverses each 1:1 mapping.
HWTEST_F(ResultCodeConverterTest, FromUserAuth_KnownCodes, TestSize.Level0)
{
    for (const auto &p : EXPECTED_PAIRS) {
        EXPECT_EQ(FromUserAuthResultCode(static_cast<int32_t>(p.ua)), p.cda);
    }
}

// Crucial ordering edge: UserAuth::FAIL must reverse to ResultCode::FAIL, not to
// ResultCode::COMMUNICATION_ERROR (which also maps to FAIL one-way). The FAIL row must stay
// ahead of COMMUNICATION_ERROR in RESULT_CODE_MAPPINGS for this to hold.
HWTEST_F(ResultCodeConverterTest, FromUserAuth_FailMapsToFailNotCommunicationError, TestSize.Level0)
{
    ResultCode reversed = FromUserAuthResultCode(static_cast<int32_t>(UserAuth::ResultCode::FAIL));
    EXPECT_EQ(reversed, ResultCode::FAIL);
    EXPECT_NE(reversed, ResultCode::COMMUNICATION_ERROR);
}

// An int with no UserAuth::ResultCode meaning falls back to GENERAL_ERROR.
HWTEST_F(ResultCodeConverterTest, FromUserAuth_UnknownIntReturnsGeneralError, TestSize.Level0)
{
    EXPECT_EQ(FromUserAuthResultCode(static_cast<int32_t>(ResultCode::CHECK_PERMISSION_FAILED)),
        ResultCode::GENERAL_ERROR);
}

// ToUserAuth then FromUserAuth round-trips for the 1:1 codes (COMMUNICATION_ERROR is excluded:
// it is lossy by design, mapping to FAIL with no way back).
HWTEST_F(ResultCodeConverterTest, RoundTrip_OneToOneCodes, TestSize.Level0)
{
    for (const auto &p : EXPECTED_PAIRS) {
        ResultCode back = FromUserAuthResultCode(static_cast<int32_t>(ToUserAuthResultCode(p.cda)));
        EXPECT_EQ(back, p.cda);
    }
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
