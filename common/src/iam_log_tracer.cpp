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

#include "iam_log_tracer.h"

#include "iam_para2str.h"
#include <string>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

bool LogTracer::IsActive() const
{
    return activeGuardCount_ > 0;
}

void LogTracer::WriteEntry(const LogEntry &entry)
{
    if (!entries_) {
        return;
    }
    (*entries_)[writeIndex_] = entry;
    writeIndex_ = (writeIndex_ + 1) % MAX_LOG_TRACE_COUNT;
    if (recordCount_ < MAX_LOG_TRACE_COUNT) {
        ++recordCount_;
    }
}

void LogTracer::Record(uint16_t fileId, uint16_t lineNum, int32_t code)
{
    if (!IsActive()) {
        return;
    }
    WriteEntry({ code, fileId, lineNum });
}

void LogTracer::Import(const std::vector<LogEntry> &entries)
{
    if (!IsActive() || entries.empty()) {
        return;
    }
    for (const auto &e : entries) {
        WriteEntry(e);
    }
}

std::vector<LogEntry> LogTracer::Export() const
{
    std::vector<LogEntry> result;
    if (!entries_) {
        return result;
    }
    result.reserve(recordCount_);
    for (uint32_t i = 0; i < recordCount_; ++i) {
        uint32_t idx = (recordCount_ < MAX_LOG_TRACE_COUNT) ? i : (writeIndex_ + i) % MAX_LOG_TRACE_COUNT;
        result.push_back((*entries_)[idx]);
    }
    return result;
}

std::string LogTracer::ExportAsString() const
{
    auto entries = Export();
    std::string result;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (i > 0) {
            result.push_back(',');
        }
        auto &e = entries[i];
        result.append(ToHexString(e.fileId));
        result.push_back('|');
        result.append(std::to_string(e.lineNum));
        result.push_back('|');
        result.append(std::to_string(e.code));
    }
    return result;
}

LogTraceGuard::LogTraceGuard()
{
    auto &tracer = LogTracer::GetInstance();
    ++tracer.activeGuardCount_;
    if (!tracer.entries_) {
        tracer.entries_ = std::make_unique<std::array<LogEntry, MAX_LOG_TRACE_COUNT>>();
    }
}

LogTraceGuard::~LogTraceGuard()
{
    auto &tracer = LogTracer::GetInstance();
    if (tracer.activeGuardCount_ > 0) {
        --tracer.activeGuardCount_;
    }
    if (tracer.activeGuardCount_ == 0) {
        if (tracer.entries_) {
            tracer.entries_->fill({});
        }
        tracer.recordCount_ = 0;
        tracer.writeIndex_ = 0;
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
