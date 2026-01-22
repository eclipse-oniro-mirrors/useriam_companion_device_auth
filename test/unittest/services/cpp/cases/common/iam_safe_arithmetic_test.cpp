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

#include "iam_safe_arithmetic.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class IamSafeArithmeticTest : public Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// ===== safe_add tests =====

HWTEST_F(IamSafeArithmeticTest, SafeAdd_Unsigned_NoOverflow, TestSize.Level0)
{
    EXPECT_EQ(safe_add(100u, 200u).value(), 300u);
    EXPECT_EQ(safe_add(0u, 0u).value(), 0u);
    EXPECT_EQ(safe_add(UINT32_MAX, 0u).value(), UINT32_MAX);
    EXPECT_EQ(safe_add(0u, UINT32_MAX).value(), UINT32_MAX);
}

HWTEST_F(IamSafeArithmeticTest, SafeAdd_Unsigned_Overflow, TestSize.Level0)
{
    EXPECT_FALSE(safe_add(UINT32_MAX, 1u).has_value());
    EXPECT_FALSE(safe_add(UINT32_MAX, UINT32_MAX).has_value());
    EXPECT_FALSE(safe_add(1u, UINT32_MAX).has_value());
}

HWTEST_F(IamSafeArithmeticTest, SafeAdd_Signed_NoOverflow, TestSize.Level0)
{
    EXPECT_EQ(safe_add(100, 200).value(), 300);
    EXPECT_EQ(safe_add(-100, 200).value(), 100);
    EXPECT_EQ(safe_add(-100, -200).value(), -300);
    EXPECT_EQ(safe_add(0, 0).value(), 0);
    EXPECT_EQ(safe_add(INT32_MAX, 0).value(), INT32_MAX);
    EXPECT_EQ(safe_add(0, INT32_MAX).value(), INT32_MAX);
    EXPECT_EQ(safe_add(INT32_MIN, 0).value(), INT32_MIN);
}

HWTEST_F(IamSafeArithmeticTest, SafeAdd_Signed_Overflow, TestSize.Level0)
{
    EXPECT_FALSE(safe_add(INT32_MAX, 1).has_value());
    EXPECT_FALSE(safe_add(1, INT32_MAX).has_value());
    EXPECT_FALSE(safe_add(INT32_MAX, INT32_MAX).has_value());
}

HWTEST_F(IamSafeArithmeticTest, SafeAdd_Signed_Underflow, TestSize.Level0)
{
    EXPECT_FALSE(safe_add(INT32_MIN, -1).has_value());
    EXPECT_FALSE(safe_add(-1, INT32_MIN).has_value());
    EXPECT_FALSE(safe_add(INT32_MIN, INT32_MIN).has_value());
}

HWTEST_F(IamSafeArithmeticTest, SafeAdd_DifferentTypes, TestSize.Level0)
{
    EXPECT_EQ(safe_add(static_cast<uint8_t>(100), static_cast<uint8_t>(200)).has_value(), false); // overflow
    EXPECT_EQ(safe_add(static_cast<uint8_t>(100), static_cast<uint8_t>(50)).value(), static_cast<uint8_t>(150));
    EXPECT_EQ(safe_add(static_cast<uint16_t>(1000), static_cast<uint16_t>(2000)).value(), static_cast<uint16_t>(3000));
    EXPECT_EQ(safe_add(static_cast<uint64_t>(1000), static_cast<uint64_t>(2000)).value(), static_cast<uint64_t>(3000));
}

// ===== safe_sub tests =====

HWTEST_F(IamSafeArithmeticTest, SafeSub_Unsigned_NoUnderflow, TestSize.Level0)
{
    EXPECT_EQ(safe_sub(300u, 200u).value(), 100u);
    EXPECT_EQ(safe_sub(200u, 200u).value(), 0u);
    EXPECT_EQ(safe_sub(UINT32_MAX, 0u).value(), UINT32_MAX);
    EXPECT_EQ(safe_sub(UINT32_MAX, 1u).value(), UINT32_MAX - 1);
}

HWTEST_F(IamSafeArithmeticTest, SafeSub_Unsigned_Underflow, TestSize.Level0)
{
    EXPECT_FALSE(safe_sub(100u, 200u).has_value());
    EXPECT_FALSE(safe_sub(0u, 1u).has_value());
    EXPECT_FALSE(safe_sub(0u, UINT32_MAX).has_value());
}

HWTEST_F(IamSafeArithmeticTest, SafeSub_Signed_NoUnderflow, TestSize.Level0)
{
    EXPECT_EQ(safe_sub(300, 200).value(), 100);
    EXPECT_EQ(safe_sub(200, 200).value(), 0);
    EXPECT_EQ(safe_sub(-100, -200).value(), 100);
    EXPECT_EQ(safe_sub(100, -200).value(), 300);
    EXPECT_EQ(safe_sub(INT32_MAX, INT32_MIN).value(), -1); // INT32_MAX - INT32_MIN = -1 (overflow wraps)
    EXPECT_EQ(safe_sub(INT32_MIN, INT32_MIN).value(), 0);
}

HWTEST_F(IamSafeArithmeticTest, SafeSub_Signed_Underflow, TestSize.Level0)
{
    EXPECT_FALSE(safe_sub(INT32_MIN, 1).has_value());
    EXPECT_FALSE(safe_sub(-100, 100).has_value());            // -100 - 100 = -200, but this should work
    EXPECT_FALSE(safe_sub(INT32_MIN, INT32_MAX).has_value()); // INT32_MIN - INT32_MAX = 1 (would underflow)
}

HWTEST_F(IamSafeArithmeticTest, SafeSub_DifferentTypes, TestSize.Level0)
{
    EXPECT_EQ(safe_sub(static_cast<uint8_t>(200), static_cast<uint8_t>(100)).value(), static_cast<uint8_t>(100));
    EXPECT_FALSE(safe_sub(static_cast<uint8_t>(100), static_cast<uint8_t>(200)).has_value());
    EXPECT_EQ(safe_sub(static_cast<uint16_t>(3000), static_cast<uint16_t>(2000)).value(), static_cast<uint16_t>(1000));
}

// ===== safe_mul tests =====

HWTEST_F(IamSafeArithmeticTest, SafeMul_Unsigned_NoOverflow, TestSize.Level0)
{
    EXPECT_EQ(safe_mul(100u, 200u).value(), 20000u);
    EXPECT_EQ(safe_mul(0u, 200u).value(), 0u);
    EXPECT_EQ(safe_mul(200u, 0u).value(), 0u);
    EXPECT_EQ(safe_mul(UINT32_MAX, 1u).value(), UINT32_MAX);
    EXPECT_EQ(safe_mul(1u, UINT32_MAX).value(), UINT32_MAX);
}

HWTEST_F(IamSafeArithmeticTest, SafeMul_Unsigned_Overflow, TestSize.Level0)
{
    EXPECT_FALSE(safe_mul(UINT32_MAX, 2u).has_value());
    EXPECT_FALSE(safe_mul(2u, UINT32_MAX).has_value());
    EXPECT_FALSE(safe_mul(0x80000000u, 2u).has_value());
    EXPECT_FALSE(safe_mul(UINT32_MAX, UINT32_MAX).has_value());
}

HWTEST_F(IamSafeArithmeticTest, SafeMul_Signed_NoOverflow, TestSize.Level0)
{
    EXPECT_EQ(safe_mul(100, 200).value(), 20000);
    EXPECT_EQ(safe_mul(100, -200).value(), -20000);
    EXPECT_EQ(safe_mul(-100, -200).value(), 20000);
    EXPECT_EQ(safe_mul(0, 200).value(), 0);
    EXPECT_EQ(safe_mul(200, 0).value(), 0);
    EXPECT_EQ(safe_mul(INT32_MAX, 1).value(), INT32_MAX);
    EXPECT_EQ(safe_mul(1, INT32_MAX).value(), INT32_MAX);
    EXPECT_EQ(safe_mul(INT32_MIN, 1).value(), INT32_MIN);
    EXPECT_EQ(safe_mul(1, INT32_MIN).value(), INT32_MIN);
}

HWTEST_F(IamSafeArithmeticTest, SafeMul_Signed_Overflow, TestSize.Level0)
{
    EXPECT_FALSE(safe_mul(INT32_MAX, 2).has_value());
    EXPECT_FALSE(safe_mul(2, INT32_MAX).has_value());
    EXPECT_FALSE(safe_mul(INT32_MIN, -1).has_value()); // Would overflow to INT32_MAX+1
}

HWTEST_F(IamSafeArithmeticTest, SafeMul_Signed_Underflow, TestSize.Level0)
{
    EXPECT_FALSE(safe_mul(INT32_MIN, 2).has_value());
    EXPECT_FALSE(safe_mul(2, INT32_MIN).has_value());
}

HWTEST_F(IamSafeArithmeticTest, SafeMul_DifferentTypes, TestSize.Level0)
{
    EXPECT_EQ(safe_mul(static_cast<uint8_t>(10), static_cast<uint8_t>(20)).value(), static_cast<uint8_t>(200));
    EXPECT_FALSE(safe_mul(static_cast<uint8_t>(20), static_cast<uint8_t>(20)).has_value()); // overflow
    EXPECT_EQ(safe_mul(static_cast<uint16_t>(100), static_cast<uint16_t>(200)).value(), static_cast<uint16_t>(20000));
}

// ===== Edge cases and combinations =====

HWTEST_F(IamSafeArithmeticTest, SafeOperations_LargeValues, TestSize.Level0)
{
    EXPECT_EQ(safe_add(static_cast<uint64_t>(10000000000ULL), static_cast<uint64_t>(20000000000ULL)).value(),
        static_cast<uint64_t>(30000000000ULL));
    EXPECT_EQ(safe_sub(static_cast<uint64_t>(30000000000ULL), static_cast<uint64_t>(20000000000ULL)).value(),
        static_cast<uint64_t>(10000000000ULL));
    EXPECT_EQ(safe_mul(static_cast<uint64_t>(100000), static_cast<uint64_t>(200000)).value(),
        static_cast<uint64_t>(20000000000ULL));
}

HWTEST_F(IamSafeArithmeticTest, SafeOperations_SizeT, TestSize.Level0)
{
    size_t a = 1000;
    size_t b = 2000;
    EXPECT_EQ(safe_add(a, b).value(), 3000ULL);
    EXPECT_EQ(safe_sub(b, a).value(), 1000ULL);
    EXPECT_EQ(safe_mul(a, b).value(), 2000000ULL);
}

HWTEST_F(IamSafeArithmeticTest, SafeOperations_OptionalUsage, TestSize.Level0)
{
    auto result1 = safe_add(100u, 200u);
    EXPECT_TRUE(result1.has_value());
    EXPECT_EQ(result1.value(), 300u);

    auto result2 = safe_add(UINT32_MAX, 1u);
    EXPECT_FALSE(result2.has_value());
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
