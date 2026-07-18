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

#include "timing_tracer.h"

#include <sstream>

#include "adapter_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

uint64_t TimingTracer::Now() const
{
    return GetTimeKeeper().GetSteadyTimeMs().value_or(0);
}

bool TimingTracer::Started() const
{
    return startMs_.has_value();
}

void TimingTracer::Start()
{
    startMs_ = Now();
    endMs_.reset();
    points_.clear();
    waitMs_ = 0;
    inWait_ = false;
    waitEnterMs_ = 0;
}

void TimingTracer::CloseWaitIfNeeded(uint64_t now)
{
    if (inWait_) {
        if (now >= waitEnterMs_) {
            waitMs_ += now - waitEnterMs_;
        }
        inWait_ = false;
    }
}

void TimingTracer::Mark(StageId id)
{
    if (!startMs_.has_value()) {
        return;
    }
    uint64_t now = Now();
    CloseWaitIfNeeded(now);
    points_.push_back(Point { id, now });
}

void TimingTracer::EnterWait(StageId id)
{
    if (!startMs_.has_value()) {
        return;
    }
    uint64_t now = Now();
    CloseWaitIfNeeded(now);
    inWait_ = true;
    waitEnterMs_ = now;
    points_.push_back(Point { id, now });
}

void TimingTracer::ExitWait(StageId id)
{
    if (!startMs_.has_value()) {
        return;
    }
    uint64_t now = Now();
    CloseWaitIfNeeded(now);
    points_.push_back(Point { id, now });
}

void TimingTracer::Finish()
{
    if (!startMs_.has_value()) {
        return;
    }
    uint64_t now = Now();
    CloseWaitIfNeeded(now);
    endMs_ = now;
}

uint64_t TimingTracer::TotalMs() const
{
    if (!startMs_.has_value() || !endMs_.has_value() || *endMs_ < *startMs_) {
        return 0;
    }
    return *endMs_ - *startMs_;
}

uint64_t TimingTracer::LocalMs() const
{
    uint64_t total = TotalMs();
    return (total >= waitMs_) ? (total - waitMs_) : 0;
}

std::string TimingTracer::ExportTrace() const
{
    if (!startMs_.has_value() || points_.empty()) {
        return "";
    }
    std::ostringstream oss;
    for (size_t i = 0; i < points_.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        uint64_t delta = (points_[i].absMs >= *startMs_) ? (points_[i].absMs - *startMs_) : 0;
        oss << points_[i].id << ":" << delta;
    }
    return oss.str();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
