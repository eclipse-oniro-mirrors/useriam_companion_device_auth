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

#ifndef COMPANION_DEVICE_AUTH_BACKOFF_RETRY_TIMER_H
#define COMPANION_DEVICE_AUTH_BACKOFF_RETRY_TIMER_H

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "nocopyable.h"

#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class BackoffRetryTimer : public NoCopyable {
public:
    using RetryCallback = std::function<void()>;

    struct Config {
        static constexpr uint32_t DEFAULT_BASE_DELAY_MS = 1;
        std::string name;
        uint32_t baseDelayMs;
        uint32_t maxDelayMs;
        uint32_t maxRetryCount { UINT32_MAX };
    };

    BackoffRetryTimer(const Config &config, RetryCallback &&callback);
    ~BackoffRetryTimer() = default;

    // Returns true if a retry was scheduled (timer still active);
    // false if retry count is exhausted and the timer can be discarded.
    bool OnFailure();
    // External trigger entry point: clear the backoff delay (so the next attempt starts from the
    // base interval) and cancel any pending retry, while preserving the failure budget. The budget
    // only bounds retries within one entry's lifetime; once exhausted the entry is dropped, so the
    // next external trigger starts a fresh budget and total retries are unbounded under sustained
    // triggers.
    void ResetBackoff();
    void Reset();

    static uint32_t CalculateNextDelayMs(uint32_t failureCount, const Config &config);

private:
    RetryCallback callback_;
    Config config_;
    uint32_t failureCount_ { 0 }; // failure budget / statistics; gates exhaustion (> maxRetryCount)
    uint32_t backoffStep_ { 0 };  // delay step; feeds CalculateNextDelayMs, reset by external trigger
    std::unique_ptr<Subscription> timerSubscription_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_BACKOFF_RETRY_TIMER_H
