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

#include <functional>
#include <memory>

#include "nocopyable.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class BackoffRetryTimer : public NoCopyable {
public:
    using RetryCallback = std::function<void()>;

    struct Config {
        uint32_t baseDelayMs;
        uint32_t maxDelayMs;
    };

    BackoffRetryTimer(const Config &config, RetryCallback &&callback);
    ~BackoffRetryTimer() = default;

    void OnFailure();
    void Reset();
    int32_t GetFailureCount() const
    {
        return failureCount_;
    }

    static uint32_t CalculateNextDelayMs(uint32_t failureCount, const Config &config);

private:
    RetryCallback callback_;
    Config config_;
    uint32_t failureCount_ { 0 };
    std::unique_ptr<Subscription> timerSubscription_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_BACKOFF_RETRY_TIMER_H
