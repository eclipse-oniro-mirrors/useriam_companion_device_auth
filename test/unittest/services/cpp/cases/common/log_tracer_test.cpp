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

#include "iam_log_tracer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class LogTracerTest : public testing::Test {
public:
    void SetUp() override
    {
        // Ensure clean state before each test
        auto entries = LogTracer::GetInstance().Export();
        EXPECT_TRUE(entries.empty());
    }

    void TearDown() override
    {
        // Drain any leftover guards
        auto entries = LogTracer::GetInstance().Export();
        EXPECT_TRUE(entries.empty());
    }
};

// Record without Guard should be no-op
HWTEST_F(LogTracerTest, RecordWithoutGuard, TestSize.Level0)
{
    LogTracer::GetInstance().Record(0x0101, 10);
    auto entries = LogTracer::GetInstance().Export();
    EXPECT_TRUE(entries.empty());
}

// Single Guard + Record
HWTEST_F(LogTracerTest, SingleGuardRecord, TestSize.Level0)
{
    {
        LogTraceGuard guard;
        LogTracer::GetInstance().Record(0x0101, 42);
        auto entries = LogTracer::GetInstance().Export();
        ASSERT_EQ(entries.size(), 1u);
        EXPECT_EQ(entries[0].fileId, 0x0101);
        EXPECT_EQ(entries[0].lineNum, 42u);
    }
    // Guard destroyed, buffer cleared
    auto entries = LogTracer::GetInstance().Export();
    EXPECT_TRUE(entries.empty());
}

// Multiple records in single scope
HWTEST_F(LogTracerTest, MultipleRecords, TestSize.Level0)
{
    {
        LogTraceGuard guard;
        LogTracer::GetInstance().Record(0x0101, 10);
        LogTracer::GetInstance().Record(0x0203, 20);
        LogTracer::GetInstance().Record(0x0110, 30);
        auto entries = LogTracer::GetInstance().Export();
        ASSERT_EQ(entries.size(), 3u);
        EXPECT_EQ(entries[0].fileId, 0x0101);
        EXPECT_EQ(entries[0].lineNum, 10u);
        EXPECT_EQ(entries[1].fileId, 0x0203);
        EXPECT_EQ(entries[1].lineNum, 20u);
        EXPECT_EQ(entries[2].fileId, 0x0110);
        EXPECT_EQ(entries[2].lineNum, 30u);
    }
}

// Nested Guard - inner destructor should not clear buffer
HWTEST_F(LogTracerTest, NestedGuard, TestSize.Level0)
{
    {
        LogTraceGuard outer;
        LogTracer::GetInstance().Record(0x0101, 1);
        {
            LogTraceGuard inner;
            LogTracer::GetInstance().Record(0x0203, 2);
            auto entries = LogTracer::GetInstance().Export();
            ASSERT_EQ(entries.size(), 2u);
        }
        // Inner destroyed, buffer should still have both entries
        auto entries = LogTracer::GetInstance().Export();
        ASSERT_EQ(entries.size(), 2u);

        LogTracer::GetInstance().Record(0x0110, 3);
        entries = LogTracer::GetInstance().Export();
        ASSERT_EQ(entries.size(), 3u);
    }
    // Outer destroyed, buffer cleared
    auto entries = LogTracer::GetInstance().Export();
    EXPECT_TRUE(entries.empty());
}

// Import batch entries
HWTEST_F(LogTracerTest, ImportEntries, TestSize.Level0)
{
    {
        LogTraceGuard guard;
        std::vector<LogEntry> imported = {
            { 0, 0x0201, 100 },
            { 0, 0x0202, 200 },
        };
        LogTracer::GetInstance().Import(imported);
        auto entries = LogTracer::GetInstance().Export();
        ASSERT_EQ(entries.size(), 2u);
        EXPECT_EQ(entries[0].fileId, 0x0201);
        EXPECT_EQ(entries[0].lineNum, 100u);
        EXPECT_EQ(entries[1].fileId, 0x0202);
        EXPECT_EQ(entries[1].lineNum, 200u);
    }
}

// Import without Guard should be no-op
HWTEST_F(LogTracerTest, ImportWithoutGuard, TestSize.Level0)
{
    std::vector<LogEntry> imported = { { 0, 0x0201, 100 } };
    LogTracer::GetInstance().Import(imported);
    auto entries = LogTracer::GetInstance().Export();
    EXPECT_TRUE(entries.empty());
}

// Circular buffer overflow
HWTEST_F(LogTracerTest, CircularBufferOverflow, TestSize.Level0)
{
    {
        LogTraceGuard guard;
        for (uint32_t i = 0; i < MAX_LOG_TRACE_COUNT + 20; ++i) {
            LogTracer::GetInstance().Record(static_cast<uint16_t>(i), static_cast<uint16_t>(i));
        }
        auto entries = LogTracer::GetInstance().Export();
        ASSERT_EQ(entries.size(), static_cast<size_t>(MAX_LOG_TRACE_COUNT));
        // Oldest entries overwritten, first entry should be index 20
        EXPECT_EQ(entries[0].fileId, 20u);
        EXPECT_EQ(entries[0].lineNum, 20u);
        // Last entry should be index 119
        EXPECT_EQ(entries[99].fileId, 119u);
        EXPECT_EQ(entries[99].lineNum, 119u);
    }
}

// ExportAsString format
HWTEST_F(LogTracerTest, ExportAsString, TestSize.Level0)
{
    {
        LogTraceGuard guard;
        LogTracer::GetInstance().Record(0x0101, 42);
        LogTracer::GetInstance().Record(0x0203, 99);
        auto str = LogTracer::GetInstance().ExportAsString();
        EXPECT_EQ(str, "0101|42|0,0203|99|0");
    }
}

// ExportAsString empty
HWTEST_F(LogTracerTest, ExportAsStringEmpty, TestSize.Level0)
{
    auto str = LogTracer::GetInstance().ExportAsString();
    EXPECT_TRUE(str.empty());
}

// Record after guard destroyed should be no-op
HWTEST_F(LogTracerTest, RecordAfterGuardDestroyed, TestSize.Level0)
{
    {
        LogTraceGuard guard;
        LogTracer::GetInstance().Record(0x0101, 1);
    }
    LogTracer::GetInstance().Record(0x0101, 2);
    auto entries = LogTracer::GetInstance().Export();
    EXPECT_TRUE(entries.empty());
}

// Sequential scopes
HWTEST_F(LogTracerTest, SequentialScopes, TestSize.Level0)
{
    {
        LogTraceGuard guard1;
        LogTracer::GetInstance().Record(0x0101, 10);
    }
    {
        LogTraceGuard guard2;
        LogTracer::GetInstance().Record(0x0203, 20);
        auto entries = LogTracer::GetInstance().Export();
        ASSERT_EQ(entries.size(), 1u);
        EXPECT_EQ(entries[0].fileId, 0x0203);
        EXPECT_EQ(entries[0].lineNum, 20u);
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
