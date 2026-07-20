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

#ifndef COMPANION_DEVICE_AUTH_TIMING_TRACER_H
#define COMPANION_DEVICE_AUTH_TIMING_TRACER_H

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class TimingTracer {
public:
    TimingTracer() = default;
    ~TimingTracer() = default;

    void Start();
    void Mark(StageId id);
    void EnterWait(StageId id);
    void ExitWait(StageId id);
    void Finish();

    bool Started() const;
    uint64_t TotalMs() const;
    uint64_t LocalMs() const;
    std::string ExportTrace() const;

private:
    struct Point {
        StageId id { 0 };
        uint64_t absMs { 0 };
    };

    uint64_t Now() const;
    void CloseWaitIfNeeded(uint64_t now);

    std::vector<Point> points_;
    std::optional<uint64_t> startMs_;
    std::optional<uint64_t> endMs_;
    uint64_t waitMs_ = 0;
    bool inWait_ = false;
    uint64_t waitEnterMs_ = 0;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TIMING_TRACER_H
