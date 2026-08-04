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

#ifndef COMPANION_DEVICE_AUTH_STALE_SUBSCRIPTION_MONITOR_H
#define COMPANION_DEVICE_AUTH_STALE_SUBSCRIPTION_MONITOR_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "nocopyable.h"

#include "access_token_kit.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class Subscription;

class StaleSubscriptionMonitor : public std::enable_shared_from_this<StaleSubscriptionMonitor>, public NoCopyable {
public:
    static std::shared_ptr<StaleSubscriptionMonitor> Create();
    ~StaleSubscriptionMonitor() = default;

    std::unique_ptr<Subscription> AddSubscription(CallerInfo caller);

private:
    StaleSubscriptionMonitor() = default;

    struct Record {
        CallerInfo caller;
        SteadyTimeMs subscribeTimeMs { 0 };
        std::optional<SteadyTimeMs> lastReportTimeMs; // empty = never reported
    };

    void RemoveSubscription(SubscribeId id);
    void UpdateScanTimer();
    void OnScanTimer();
    void ReportStale(const Record &rec, SteadyTimeMs ageMs);

    std::unordered_map<SubscribeId, Record> records_;
    std::unique_ptr<Subscription> scanTimerSubscription_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_STALE_SUBSCRIPTION_MONITOR_H
