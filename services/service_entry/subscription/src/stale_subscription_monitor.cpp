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

#include "stale_subscription_monitor.h"

#include <algorithm>
#include <new>
#include <sstream>
#include <string>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_safe_arithmetic.h"

#include "accesstoken_kit.h"
#include "adapter_manager.h"
#include "event_manager_adapter.h"
#include "relative_timer.h"
#include "singleton_manager.h"
#include "subscription.h"

#undef LOG_TAG
#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_STALE_SUBSCRIPTION_MONITOR

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr SteadyTimeMs MS_PER_SECOND = 1000;
constexpr SteadyTimeMs FIRST_REPORT_MS = 60 * 60 * MS_PER_SECOND; // 1h
constexpr SteadyTimeMs MIN_GAP_MS = 24 * 60 * 60 * MS_PER_SECOND; // 24h (daily)
constexpr uint32_t SCAN_INTERVAL_MS = 60 * 60 * MS_PER_SECOND;    // 1h

} // namespace

std::shared_ptr<StaleSubscriptionMonitor> StaleSubscriptionMonitor::Create()
{
    auto monitor = std::shared_ptr<StaleSubscriptionMonitor>(new (std::nothrow) StaleSubscriptionMonitor());
    ENSURE_OR_RETURN_VAL(monitor != nullptr, nullptr);
    return monitor;
}

std::unique_ptr<Subscription> StaleSubscriptionMonitor::AddSubscription(CallerInfo caller)
{
    auto now = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN_VAL(now.has_value(), nullptr);
    SubscribeId id = GetMiscManager().GetNextGlobalId();
    records_[id] = Record { std::move(caller), now.value() };
    UpdateScanTimer();
    return std::make_unique<Subscription>([weakSelf = weak_from_this(), id]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->RemoveSubscription(id);
    });
}

void StaleSubscriptionMonitor::RemoveSubscription(SubscribeId id)
{
    records_.erase(id);
    UpdateScanTimer();
}

void StaleSubscriptionMonitor::UpdateScanTimer()
{
    bool needTimer = !records_.empty();
    bool hasTimer = scanTimerSubscription_ != nullptr;

    if (needTimer == hasTimer) {
        return;
    }
    if (!needTimer) {
        scanTimerSubscription_.reset();
        return;
    }
    if (!hasTimer) {
        scanTimerSubscription_ = RelativeTimer::GetInstance().RegisterPeriodic(
            [weakSelf = weak_from_this()]() {
                auto self = weakSelf.lock();
                ENSURE_OR_RETURN(self != nullptr);
                self->OnScanTimer();
            },
            SCAN_INTERVAL_MS);
        ENSURE_OR_RETURN(scanTimerSubscription_ != nullptr);
    }
}

void StaleSubscriptionMonitor::OnScanTimer()
{
    auto nowOpt = GetTimeKeeper().GetSteadyTimeMs();
    ENSURE_OR_RETURN(nowOpt.has_value());
    SteadyTimeMs now = nowOpt.value();
    for (auto &item : records_) {
        auto &rec = item.second;
        auto ageOpt = SafeSub(now, rec.subscribeTimeMs);
        ENSURE_OR_CONTINUE(ageOpt.has_value());
        SteadyTimeMs age = ageOpt.value();
        bool shouldReport = age >= FIRST_REPORT_MS;
        bool isSuppressed = false;
        if (rec.lastReportTimeMs.has_value()) {
            auto gapOpt = SafeSub(now, rec.lastReportTimeMs.value());
            ENSURE_OR_CONTINUE(gapOpt.has_value());
            isSuppressed = gapOpt.value() < MIN_GAP_MS;
        }
        if (shouldReport && !isSuppressed) {
            ReportStale(rec, age);
            rec.lastReportTimeMs = now;
        }
    }
}

void StaleSubscriptionMonitor::ReportStale(const Record &rec, SteadyTimeMs ageMs)
{
    std::string foregroundStr = "n/a";
    if (rec.caller.type == CallerTokenType::Hap) {
        const auto &foregroundApps = GetAppForegroundStateAdapter().GetForegroundWatchedApps();
        bool foreground =
            std::find(foregroundApps.begin(), foregroundApps.end(), rec.caller.name) != foregroundApps.end();
        foregroundStr = foreground ? "1" : "0";
    }
    std::ostringstream detail;
    detail << "callerName:" << rec.caller.name << ";pid:" << rec.caller.pid << ";uid:" << rec.caller.uid
           << ";callerType:" << static_cast<int32_t>(rec.caller.type) << ";foreground:" << foregroundStr
           << ";ageSec:" << (ageMs / MS_PER_SECOND);
    IAM_LOGI("subscription not released: %{public}s", detail.str().c_str());
    ReportSystemFault("STALE_SUBSCRIPTION", rec.caller.name, detail.str());
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
