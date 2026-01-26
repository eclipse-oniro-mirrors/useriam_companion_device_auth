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

#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#include "backoff_retry_timer.h"
#include "iam_logger.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t NUM_0 = 0;
constexpr uint32_t NUM_1 = 1;
constexpr uint32_t NUM_2 = 2;
constexpr uint32_t NUM_3 = 3;
constexpr uint32_t NUM_4 = 4;
constexpr uint32_t NUM_5 = 5;
constexpr uint32_t NUM_6 = 6;
constexpr uint32_t NUM_7 = 7;
constexpr uint32_t NUM_10 = 10;
constexpr uint32_t NUM_11 = 11;
constexpr uint32_t NUM_100 = 100;
constexpr uint32_t NUM_200 = 200;
constexpr uint32_t NUM_1000 = 1000;
constexpr uint32_t NUM_1234 = 1234;
constexpr uint32_t NUM_1024 = 1024;
constexpr uint32_t NUM_2000 = 2000;
constexpr uint32_t NUM_4000 = 4000;
constexpr uint32_t NUM_5000 = 5000;
constexpr uint32_t NUM_8000 = 8000;
constexpr uint32_t NUM_10000 = 10000;
constexpr uint32_t NUM_16000 = 16000;
constexpr uint32_t NUM_32000 = 32000;
constexpr uint32_t NUM_60000 = 60000;
constexpr uint32_t NUM_64000 = 64000;
constexpr uint32_t NUM_100000 = 100000;
constexpr uint32_t NUM_200000 = 200000;
constexpr uint32_t NUM_400000 = 400000;
constexpr uint32_t NUM_600000 = 600000;
constexpr uint32_t NUM_10000000 = 10000000;
constexpr uint32_t NUM_MAX_SHIFT_COUNT = 31;
} // namespace

class BackoffRetryTimerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }

    static void TearDownTestCase()
    {
    }

    void SetUp()
    {
    }

    void TearDown()
    {
    }
};

HWTEST_F(BackoffRetryTimerTest, OnFailure_IncreasesCount, TestSize.Level0)
{
    int callbackCount = 0;
    BackoffRetryTimer timer({ .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 },
        [&callbackCount]() { callbackCount++; });

    EXPECT_EQ(timer.GetFailureCount(), 0);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 2);
}

HWTEST_F(BackoffRetryTimerTest, Destructor_CancelsTimer, TestSize.Level0)
{
    int callbackCount = 0;

    {
        BackoffRetryTimer timer({ .baseDelayMs = NUM_100, .maxDelayMs = NUM_60000 },
            [&callbackCount]() { callbackCount++; });
        timer.OnFailure();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(NUM_200));
    EXPECT_EQ(callbackCount, 0);
}

HWTEST_F(BackoffRetryTimerTest, MultipleFailures_ExponentialBackoff, TestSize.Level0)
{
    BackoffRetryTimer timer({ .baseDelayMs = NUM_1000, .maxDelayMs = NUM_32000 }, []() {});

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 2);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 3);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 4);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 5);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 6);
}

HWTEST_F(BackoffRetryTimerTest, CustomConfig, TestSize.Level0)
{
    BackoffRetryTimer timer({ .baseDelayMs = NUM_2000, .maxDelayMs = NUM_10000 }, []() {});

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);
}

HWTEST_F(BackoffRetryTimerTest, Reset_ResetsFailureCount, TestSize.Level0)
{
    BackoffRetryTimer timer({ .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 }, []() {});

    EXPECT_EQ(timer.GetFailureCount(), 0);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 2);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 3);

    timer.Reset();
    EXPECT_EQ(timer.GetFailureCount(), 0);

    // After reset, failures should start from 0 again
    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 2);
}

HWTEST_F(BackoffRetryTimerTest, Reset_CancelsPendingTimer, TestSize.Level0)
{
    int callbackCount = 0;
    BackoffRetryTimer timer({ .baseDelayMs = NUM_100, .maxDelayMs = NUM_60000 },
        [&callbackCount]() { callbackCount++; });

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);

    // Reset immediately
    timer.Reset();

    // Wait for the original timer to expire (should not execute)
    std::this_thread::sleep_for(std::chrono::milliseconds(NUM_200));
    EXPECT_EQ(callbackCount, 0);
    EXPECT_EQ(timer.GetFailureCount(), 0);
}

HWTEST_F(BackoffRetryTimerTest, Reset_AfterMultipleFailures, TestSize.Level0)
{
    BackoffRetryTimer timer({ .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 }, []() {});

    timer.OnFailure();
    timer.OnFailure();
    timer.OnFailure();
    timer.OnFailure();
    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 5);

    timer.Reset();
    EXPECT_EQ(timer.GetFailureCount(), 0);

    // Verify backoff restarts from beginning
    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);
}

HWTEST_F(BackoffRetryTimerTest, Reset_MultipleTimes, TestSize.Level0)
{
    BackoffRetryTimer timer({ .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 }, []() {});

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);

    timer.Reset();
    EXPECT_EQ(timer.GetFailureCount(), 0);

    timer.Reset();
    EXPECT_EQ(timer.GetFailureCount(), 0);

    timer.OnFailure();
    EXPECT_EQ(timer.GetFailureCount(), 1);

    timer.Reset();
    EXPECT_EQ(timer.GetFailureCount(), 0);
}

// Test the static CalculateNextDelayMs function with boundary cases
class BackoffRetryTimerCalculateTest : public testing::Test {};

HWTEST_F(BackoffRetryTimerCalculateTest, FailureCount_Zero_ReturnsBaseDelay, TestSize.Level0)
{
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_0, config), NUM_1000);
}

HWTEST_F(BackoffRetryTimerCalculateTest, FailureCount_One_ReturnsBaseDelay, TestSize.Level0)
{
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_1, config), NUM_1000);
}

HWTEST_F(BackoffRetryTimerCalculateTest, FailureCount_Two_ReturnsDoubleBaseDelay, TestSize.Level0)
{
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), NUM_2000);
}

HWTEST_F(BackoffRetryTimerCalculateTest, FailureCount_Three_ReturnsQuadrupleBaseDelay, TestSize.Level0)
{
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_3, config), NUM_4000);
}

HWTEST_F(BackoffRetryTimerCalculateTest, FailureCount_Four_ReturnsEightTimesBaseDelay, TestSize.Level0)
{
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = NUM_60000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_4, config), NUM_8000);
}

HWTEST_F(BackoffRetryTimerCalculateTest, ExponentialBackoff_Sequence, TestSize.Level0)
{
    // Verify exponential backoff sequence: delay doubles after each failure starting from the 2nd failure
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = NUM_100000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_0, config), NUM_1000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_1, config), NUM_1000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), NUM_2000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_3, config), NUM_4000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_4, config), NUM_8000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_5, config), NUM_16000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_6, config), NUM_32000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_7, config), NUM_64000);
}

HWTEST_F(BackoffRetryTimerCalculateTest, MaxDelay_CappedAtMax, TestSize.Level0)
{
    // Verify delay is capped at maxDelayMs and never exceeds it
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = NUM_5000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), NUM_2000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_3, config), NUM_4000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_4, config), NUM_5000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_5, config), NUM_5000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_10, config), NUM_5000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_100, config), NUM_5000);
}

HWTEST_F(BackoffRetryTimerCalculateTest, MaxShiftCount_Exceeded, TestSize.Level0)
{
    // Verify that shifting beyond maximum bit count returns UINT32_MAX to prevent overflow
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = UINT32_MAX };
    const uint32_t lastValidShiftCount = NUM_MAX_SHIFT_COUNT + 1;
    const uint32_t firstInvalidShiftCount = NUM_MAX_SHIFT_COUNT + NUM_2;
    const uint32_t secondInvalidShiftCount = NUM_MAX_SHIFT_COUNT + NUM_3;
    const uint32_t largeFailureCount = NUM_100;

    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(lastValidShiftCount, config), NUM_1000 << NUM_MAX_SHIFT_COUNT);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(firstInvalidShiftCount, config), UINT32_MAX);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(secondInvalidShiftCount, config), UINT32_MAX);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(largeFailureCount, config), UINT32_MAX);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(UINT32_MAX, config), UINT32_MAX);
}

HWTEST_F(BackoffRetryTimerCalculateTest, EdgeCase_BaseDelayZero, TestSize.Level0)
{
    BackoffRetryTimer::Config config = { .baseDelayMs = 0, .maxDelayMs = NUM_60000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_0, config), 0);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_1, config), 0);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), 0);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_100, config), 0);
}

HWTEST_F(BackoffRetryTimerCalculateTest, EdgeCase_BaseDelayEqualsMaxDelay, TestSize.Level0)
{
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_5000, .maxDelayMs = NUM_5000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_0, config), NUM_5000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_1, config), NUM_5000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config),
        NUM_5000); // NUM_5000 << 1 = NUM_10000, capped to NUM_5000
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_100, config), NUM_5000);
}

HWTEST_F(BackoffRetryTimerCalculateTest, EdgeCase_LargeBaseDelay, TestSize.Level0)
{
    // Test with large baseDelayMs values
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_100000, .maxDelayMs = NUM_600000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_0, config), NUM_100000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_1, config), NUM_100000);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), NUM_200000); // NUM_100000 << 1
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_3, config), NUM_400000); // NUM_100000 << 2
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_4, config),
        NUM_600000); // NUM_100000 << 3 = NUM_800000 capped
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_5, config), NUM_600000); // capped
}

HWTEST_F(BackoffRetryTimerCalculateTest, EdgeCase_MaxDelayZero, TestSize.Level0)
{
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1000, .maxDelayMs = 0 };
    // Even though this is an invalid config, function should not crash
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_0, config), 0);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), 0);
}

HWTEST_F(BackoffRetryTimerCalculateTest, EdgeCase_BaseDelayLargerThanMaxDelay, TestSize.Level0)
{
    // Invalid config but should handle gracefully
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_10000, .maxDelayMs = NUM_5000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_0, config), NUM_10000); // returns baseDelayMs
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_1, config), NUM_10000); // returns baseDelayMs
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config),
        NUM_5000); // NUM_10000 << 1 = NUM_20000, capped to NUM_5000
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_10, config), NUM_5000); // capped to maxDelayMs
}

HWTEST_F(BackoffRetryTimerCalculateTest, BitShift_PowerOfTwo_BaseDelay, TestSize.Level0)
{
    // Use power of 2 for baseDelay to verify exact bit shifts
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1024, .maxDelayMs = UINT32_MAX };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), NUM_1024 << 1);   // NUM_1024 * 2^1
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_3, config), NUM_1024 << 2);   // NUM_1024 * 2^2
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_4, config), NUM_1024 << 3);   // NUM_1024 * 2^3
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_11, config), NUM_1024 << 10); // NUM_1024 * 2^10
}

HWTEST_F(BackoffRetryTimerCalculateTest, LargeValues_NoOverflow, TestSize.Level0)
{
    // Test with values that would overflow if not careful
    BackoffRetryTimer::Config config = { .baseDelayMs = UINT32_MAX, .maxDelayMs = UINT32_MAX };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_0, config), UINT32_MAX);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_1, config), UINT32_MAX);
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), UINT32_MAX); // capped
}

HWTEST_F(BackoffRetryTimerCalculateTest, PrecisionCheck_MidRangeValues, TestSize.Level0)
{
    // Test odd numbers to ensure exact calculations
    BackoffRetryTimer::Config config = { .baseDelayMs = NUM_1234, .maxDelayMs = NUM_10000000 };
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_2, config), NUM_1234 << 1); // NUM_1234 * 2^1 = NUM_2468
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_3, config), NUM_1234 << 2); // NUM_1234 * 2^2 = NUM_4936
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_4, config), NUM_1234 << 3); // NUM_1234 * 2^3 = NUM_9872
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_5, config), NUM_1234 << 4); // NUM_1234 * 2^4 = NUM_19744
    EXPECT_EQ(BackoffRetryTimer::CalculateNextDelayMs(NUM_6, config), NUM_1234 << 5); // NUM_1234 * 2^5 = NUM_39488
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
