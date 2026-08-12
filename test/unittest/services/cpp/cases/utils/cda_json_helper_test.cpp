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

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "cda_json_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

namespace {
// The helpers under test parse cross-device peer payloads, so the boundary and
// type-mismatch cases below mirror what a malformed or hostile peer could send.
class CdaJsonHelperTest : public Test {
    // Header-only utilities — no MockGuard needed.
};
} // namespace

// ---------- TryParseJson ----------

HWTEST_F(CdaJsonHelperTest, TryParseJson_ValidObject_HasValue, TestSize.Level0)
{
    auto json = TryParseJson(R"({"deviceIdType":1,"deviceId":"abc"})");
    ASSERT_TRUE(json.has_value());
    EXPECT_TRUE(json->is_object());
}

HWTEST_F(CdaJsonHelperTest, TryParseJson_Malformed_ReturnsNullopt, TestSize.Level0)
{
    EXPECT_FALSE(TryParseJson(R"(not json{)").has_value());
    EXPECT_FALSE(TryParseJson("").has_value()); // empty input is not a valid JSON document
    EXPECT_FALSE(TryParseJson(R"({"k":})").has_value()); // truncated value
}

HWTEST_F(CdaJsonHelperTest, TryParseJson_BytesOverload_ParsesLikeString, TestSize.Level0)
{
    const std::string text = R"({"remoteTokenId":7})";
    std::vector<uint8_t> bytes(text.begin(), text.end());
    auto json = TryParseJson(bytes);
    ASSERT_TRUE(json.has_value());
    uint32_t tokenId = 0;
    EXPECT_TRUE(GetJsonField(*json, "remoteTokenId", tokenId));
    EXPECT_EQ(tokenId, 7u);
}

HWTEST_F(CdaJsonHelperTest, TryParseJson_BytesOverload_GarbageReturnsNullopt, TestSize.Level0)
{
    std::vector<uint8_t> bytes = { 0xDE, 0xAD, 0xBE, 0xEF };
    EXPECT_FALSE(TryParseJson(bytes).has_value());
}

// ---------- GetJsonField: signed integral ----------

HWTEST_F(CdaJsonHelperTest, GetJsonField_Signed_AcceptsInRange, TestSize.Level0)
{
    auto json = TryParseJson(R"({"pos":100,"neg":-100})");
    ASSERT_TRUE(json.has_value());
    int32_t pos = 0;
    int32_t neg = 0;
    EXPECT_TRUE(GetJsonField(*json, "pos", pos));
    EXPECT_TRUE(GetJsonField(*json, "neg", neg));
    EXPECT_EQ(pos, 100);
    EXPECT_EQ(neg, -100);
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_Signed_AcceptsBoundaries, TestSize.Level0)
{
    auto json = TryParseJson(R"({"max":2147483647,"min":-2147483648})");
    ASSERT_TRUE(json.has_value());
    int32_t maxV = 0;
    int32_t minV = 0;
    EXPECT_TRUE(GetJsonField(*json, "max", maxV));
    EXPECT_TRUE(GetJsonField(*json, "min", minV));
    EXPECT_EQ(maxV, std::numeric_limits<int32_t>::max());
    EXPECT_EQ(minV, std::numeric_limits<int32_t>::min());
}

// A positive value just over INT32_MAX is stored unsigned and must be rejected,
// not silently truncated into a wrapped/negative int32_t.
HWTEST_F(CdaJsonHelperTest, GetJsonField_Signed_RejectsOverflow, TestSize.Level0)
{
    auto json = TryParseJson(R"({"v":2147483648,"w":-2147483649})");
    ASSERT_TRUE(json.has_value());
    int32_t v = 0;
    int32_t w = 0;
    EXPECT_FALSE(GetJsonField(*json, "v", v)); // INT32_MAX + 1
    EXPECT_FALSE(GetJsonField(*json, "w", w)); // INT32_MIN - 1
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_Signed_RejectsNonInteger, TestSize.Level0)
{
    auto json = TryParseJson(R"({"f":1.5,"b":true,"s":"3"})");
    ASSERT_TRUE(json.has_value());
    int32_t f = 0;
    int32_t b = 0;
    int32_t s = 0;
    EXPECT_FALSE(GetJsonField(*json, "f", f)); // float
    EXPECT_FALSE(GetJsonField(*json, "b", b)); // bool
    EXPECT_FALSE(GetJsonField(*json, "s", s)); // string
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_Signed_MissingKeyReturnsFalse, TestSize.Level0)
{
    auto json = TryParseJson(R"({"other":1})");
    ASSERT_TRUE(json.has_value());
    int32_t v = 0;
    EXPECT_FALSE(GetJsonField(*json, "absent", v));
}

// ---------- GetJsonField: unsigned integral ----------

HWTEST_F(CdaJsonHelperTest, GetJsonField_Unsigned_AcceptsInRangeAndMax, TestSize.Level0)
{
    auto json = TryParseJson(R"({"v":42,"max":4294967295})");
    ASSERT_TRUE(json.has_value());
    uint32_t v = 0;
    uint32_t maxV = 0;
    EXPECT_TRUE(GetJsonField(*json, "v", v));
    EXPECT_TRUE(GetJsonField(*json, "max", maxV));
    EXPECT_EQ(v, 42u);
    EXPECT_EQ(maxV, std::numeric_limits<uint32_t>::max());
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_Unsigned_RejectsOverflow, TestSize.Level0)
{
    auto json = TryParseJson(R"({"v":4294967296})"); // UINT32_MAX + 1
    ASSERT_TRUE(json.has_value());
    uint32_t v = 0;
    EXPECT_FALSE(GetJsonField(*json, "v", v));
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_Unsigned_RejectsNegative, TestSize.Level0)
{
    auto json = TryParseJson(R"({"v":-1})");
    ASSERT_TRUE(json.has_value());
    uint32_t v = 0;
    EXPECT_FALSE(GetJsonField(*json, "v", v));
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_Unsigned_RejectsNonInteger, TestSize.Level0)
{
    auto json = TryParseJson(R"({"f":1.5,"s":"3"})");
    ASSERT_TRUE(json.has_value());
    uint32_t f = 0;
    uint32_t s = 0;
    EXPECT_FALSE(GetJsonField(*json, "f", f)); // float
    EXPECT_FALSE(GetJsonField(*json, "s", s)); // string
}

// ---------- GetJsonField: string ----------

HWTEST_F(CdaJsonHelperTest, GetJsonField_String_AcceptsAndEmpty, TestSize.Level0)
{
    auto json = TryParseJson(R"({"d":"abc","e":""})");
    ASSERT_TRUE(json.has_value());
    std::string d;
    std::string e = "untouched";
    EXPECT_TRUE(GetJsonField(*json, "d", d, 256));
    EXPECT_EQ(d, "abc");
    EXPECT_TRUE(GetJsonField(*json, "e", e, 256));
    EXPECT_TRUE(e.empty());
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_String_AcceptsExactMaxLen, TestSize.Level0)
{
    constexpr size_t maxLen = 256;
    auto json = TryParseJson(std::string(R"({"d":")") + std::string(maxLen, 'x') + R"("})");
    ASSERT_TRUE(json.has_value());
    std::string d;
    EXPECT_TRUE(GetJsonField(*json, "d", d, maxLen));
    EXPECT_EQ(d.size(), maxLen);
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_String_RejectsOverMaxLen, TestSize.Level0)
{
    constexpr size_t maxLen = 256;
    auto json = TryParseJson(std::string(R"({"d":")") + std::string(maxLen + 1, 'x') + R"("})");
    ASSERT_TRUE(json.has_value());
    std::string d = "untouched";
    EXPECT_FALSE(GetJsonField(*json, "d", d, maxLen));
    EXPECT_EQ(d, "untouched"); // out left unmodified on rejection
}

HWTEST_F(CdaJsonHelperTest, GetJsonField_String_RejectsNonStringAndMissing, TestSize.Level0)
{
    auto json = TryParseJson(R"({"n":1})");
    ASSERT_TRUE(json.has_value());
    std::string d = "untouched";
    EXPECT_FALSE(GetJsonField(*json, "n", d, 256)); // integer, not string
    EXPECT_FALSE(GetJsonField(*json, "absent", d, 256)); // missing
    EXPECT_EQ(d, "untouched");
}
