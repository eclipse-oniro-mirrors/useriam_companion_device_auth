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
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

#include "cda_secure_vector.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

namespace {
// SecureVector is a security primitive: it must be move-only (copying would
// spread the secret to buffers the caller may not clear) but fully movable.
static_assert(!std::is_copy_constructible<SecureVector>::value, "SecureVector must be move-only");
static_assert(!std::is_copy_assignable<SecureVector>::value, "SecureVector must be move-only");
static_assert(std::is_move_constructible<SecureVector>::value, "SecureVector must be movable");
static_assert(std::is_move_assignable<SecureVector>::value, "SecureVector must be movable");
} // namespace

class SecureVectorTest : public testing::Test {
public:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// Clear() must zeroize the underlying buffer in place, not merely drop the size.
HWTEST_F(SecureVectorTest, Clear_ZeroesBuffer, TestSize.Level0)
{
    const std::vector<uint8_t> bytes = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    SecureVector v(bytes.begin(), bytes.end());
    ASSERT_EQ(v.Get().size(), bytes.size());

    const uint8_t *ptr = v.Get().data();
    size_t n = v.Get().size();
    ASSERT_NE(ptr, nullptr);
    for (size_t i = 0; i < n; ++i) {
        EXPECT_NE(ptr[i], 0); // non-zero before clear
    }

    v.Clear();
    // Clear() zeroizes via memset_s then drops size; the capacity buffer is still
    // allocated, so the zeroed bytes remain observable through the captured pointer.
    EXPECT_TRUE(v.Get().empty());
    for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(ptr[i], 0); // wiped
    }
}

// Adopt-by-copy ctor (const vector&) — mirrors the ext SecureVector usage.
HWTEST_F(SecureVectorTest, ConstructFromConstVector_HoldsCopy, TestSize.Level0)
{
    const std::vector<uint8_t> src = { 0xAA, 0xBB, 0xCC };
    SecureVector v(src);
    EXPECT_EQ(v.Get().size(), src.size());
    EXPECT_EQ(v.Get(), src);
}

// Move-from plain vector ctor — the secret is adopted, the source is emptied so
// it no longer holds a plaintext copy (the NAPI fill path relies on this).
HWTEST_F(SecureVectorTest, MoveFromVector_AdoptsBuffer, TestSize.Level0)
{
    std::vector<uint8_t> raw = { 0x01, 0x02, 0x03, 0x04 };
    const uint8_t *rawPtr = raw.data();
    SecureVector v(std::move(raw));
    EXPECT_TRUE(raw.empty());
    ASSERT_EQ(v.Get().size(), 4u);
    EXPECT_EQ(v.Get().data(), rawPtr); // same buffer, not a copy
}

// Move ctor — destination owns the data, source becomes empty.
HWTEST_F(SecureVectorTest, MoveCtor_TransfersOwnership, TestSize.Level0)
{
    SecureVector a(std::vector<uint8_t> { 0x10, 0x20, 0x30 });
    SecureVector b(std::move(a));
    EXPECT_TRUE(a.Get().empty());
    ASSERT_EQ(b.Get().size(), 3u);
    EXPECT_EQ(b.Get()[0], 0x10);
    EXPECT_EQ(b.Get()[2], 0x30);
}

// Move assignment — destination owns the data, source becomes empty.
HWTEST_F(SecureVectorTest, MoveAssign_TransfersOwnership, TestSize.Level0)
{
    SecureVector a(std::vector<uint8_t> { 0x09, 0x08 });
    SecureVector b;
    b = std::move(a);
    EXPECT_TRUE(a.Get().empty());
    ASSERT_EQ(b.Get().size(), 2u);
    EXPECT_EQ(b.Get()[1], 0x08);
}

// Empty buffer — Clear() is a safe no-op (no memset on null/zero size).
HWTEST_F(SecureVectorTest, EmptyBuffer_ClearIsNoOp, TestSize.Level0)
{
    SecureVector v;
    EXPECT_NO_THROW(v.Clear());
    EXPECT_TRUE(v.Get().empty());
}
