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

#include "backoff_retry_timer.h"

#include <cstdint>
#include <limits>

#include "iam_check.h"
#include "iam_logger.h"
#include "relative_timer.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

BackoffRetryTimer::BackoffRetryTimer(const Config &config, RetryCallback &&callback)
    : callback_(std::move(callback)),
      config_(config)
{
}

void BackoffRetryTimer::OnFailure()
{
    if (timerSubscription_ != nullptr) {
        timerSubscription_.reset();
    }

    failureCount_++;

    uint32_t delayMs = CalculateNextDelayMs(failureCount_, config_);
    IAM_LOGI("failure recorded %{public}u times, scheduling retry in %{public}u ms", failureCount_, delayMs);

    timerSubscription_ = RelativeTimer::GetInstance().Register(
        [callback = callback_]() {
            IAM_LOGI("executing retry callback");
            ENSURE_OR_RETURN(callback != nullptr);
            callback();
        },
        delayMs);
}

void BackoffRetryTimer::Reset()
{
    if (timerSubscription_ != nullptr) {
        timerSubscription_.reset();
    }
    failureCount_ = 0;
    IAM_LOGI("retry timer reset");
}

uint32_t BackoffRetryTimer::CalculateNextDelayMs(uint32_t failureCount, const Config &config)
{
    constexpr uint32_t NUM_MAX_SHIFT_COUNT = 31;
    if (failureCount <= 1) {
        return config.baseDelayMs;
    }

    uint32_t shiftCount = failureCount - 1;
    if (shiftCount > NUM_MAX_SHIFT_COUNT) {
        return config.maxDelayMs;
    }

    uint64_t delayMs = config.baseDelayMs;
    delayMs <<= shiftCount;
    if (delayMs > config.maxDelayMs) {
        return config.maxDelayMs;
    }
    return static_cast<uint32_t>(delayMs);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
